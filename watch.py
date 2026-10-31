#!/usr/bin/env python
"""
watch.py — track when watched MACs arrive/leave the eero network(s).

Single file of state (watch.state.json) — contains current per-device state,
recent run history, and a bounded transition log. No external JSONL files.

Model: "LAN ESTABLISHES, eero SUSTAINS" — uniform for every device.

  LAN is the source of truth. A device is confirmed present only by answering a
  live LAN probe (arping/TCP/ping/ping6, MAC-verified). eero is used for
  DISCOVERY (current IPs/MACs/link-locals to probe) and as a SUSTAIN signal
  only — its `connected` flag can never make an away device arrive, because
  eero reports devices as connected that aren't actually here (phantom/edge
  associations). It is too noisy to establish presence; it is only trusted to
  hold an already-LAN-confirmed device through Wi-Fi power-save sleep gaps.

  Per run (judge_presence) yields two facts: lan_ok (a LAN probe answered) and
  eero_conn (eero says connected=True). run_once derives:
    sustain = HOME and eero_conn and (last LAN hit within EERO_SUSTAIN_MAX_MIN,
              or the device's own eero_sustain_max_min override)
    vouch   = lan_ok or sustain
  A device that never answers LAN has no recent LAN hit, so eero can't sustain
  it — it cannot stay (or become) HOME on eero alone.

  Transitions (decide_state_change):
    AWAY -> HOME      : >= CONSEC_TO_ARRIVE LAN hits within the last
                        ARRIVE_WINDOW runs (LAN only — eero cannot arrive).
    HOME -> AWAY      : no vouch (no LAN hit and no valid eero-sustain) for
                        LEAVE_MINUTES.
    HOME@X -> HOME@Y  : eero places the device on a different network.
"""

import json
import os
import re
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import eero as eero_pkg
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from config import get as _cfg
from utils import (
	now_ny , parse_eero_time , fmt_dt_short , to_iso , from_iso ,
	humanize_duration ,
	normalize_mac , extract_eero_signals ,
	extract_eero_ips , extract_device_ipv6_link_locals , eui64_embedded_mac ,
	as_mac_set ,
	CookieStore ,
	send_notification ,
	verify_on_lan ,
	ENABLE_LOCAL_PROBES ,
)

# Rich console — when run under cron (no TTY) the default width is 80 cols
# which mangles our wide table. Detect TTY and use a wider fixed width + plain
# (no ANSI) output in that case, so log files stay readable.
_IS_TTY = sys.stdout.isatty()
_LOG_WIDTH = int( os.environ.get( "WATCH_WIDTH" , "200" ) )  # override via env if needed
_console = Console(
	width=None if _IS_TTY else _LOG_WIDTH ,
	color_system="auto" if _IS_TTY else None ,
	force_terminal=_IS_TTY ,
	highlight=False ,
)

# Verbose [fetch] diagnostic. Off by default to keep cron logs clean.
# Enable with: WATCH2_DEBUG=1 python watch.py
_DEBUG = bool( os.environ.get( "WATCH_DEBUG" ) )


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

STATE_PATH = Path( _cfg( "paths.state" , "watch.state.json" ) )
COOKIE_PATH = _cfg( "paths.cookie" , "session.cookie" )

# eero probing
PROBES_PER_RUN = _cfg( "probing.probes_per_run" , 2 )
PROBE_DELAY_SEC = _cfg( "probing.probe_delay_sec" , 1.0 )

# --- Presence model "LAN establishes, eero sustains" (see module docstring).
# All values from config.yaml; comments document meaning. ---

# ARRIVE: need this many LAN probe hits within the last ARRIVE_WINDOW runs to
# flip AWAY -> HOME. LAN only — eero can never arrive a device.
CONSEC_TO_ARRIVE = _cfg( "presence.consec_to_arrive" , 2 )
ARRIVE_WINDOW    = _cfg( "presence.arrive_window" , 10 )

# LEFT: declare gone after this many minutes with no vouch — no LAN hit AND no
# valid eero-sustain. Time-based, independent of cron interval.
LEAVE_MINUTES = _cfg( "presence.leave_minutes" , 5 )

# eero `connected=True` may SUSTAIN an already-home device through Wi-Fi
# power-save sleep gaps, but only while the last LAN hit is younger than this.
# Past it, eero alone no longer counts — so a device that stops answering LAN
# entirely (gone, or a phantom that never answered) is allowed to leave.
EERO_SUSTAIN_MAX_MIN = _cfg( "presence.eero_sustain_max_min" , 30 )

# State retention
HISTORY_WINDOW = _cfg( "state.history_window" , 60 )       # per-device, last N runs P/_
MAX_EVENTS_KEPT = _cfg( "state.max_events_kept" , 200 )    # bounded transition log

# Notifications
NOTIFICATION_COOLDOWN_MIN = _cfg( "notifications.cooldown_min" , 15 )

# eero network this instance watches (None/null => every network on the account).
MY_NETWORK = _cfg( "network" , None )

def _norm_name( s ):
	"""Case/whitespace/curly-apostrophe-insensitive name key for matching eero
	name fields against watched names ('Alex’s iPhone' == \"Alex's iPhone\")."""
	if not s:
		return ""
	s = str( s ).replace( "’" , "'" ).replace( "‘" , "'" ).replace( "ʼ" , "'" )
	return " ".join( s.lower().split() )

# WATCHED is keyed by the human-friendly DEVICE NAME; each value declares how to
# recognize that physical device in eero's list — { "names": [...], "macs": [...] }.
# A record matches if ANY name OR ANY mac matches; state/notifications are tracked
# per-name. Defined in config.yaml (-> watched); see the comments there. The
# bare-list legacy form (value = list of MACs) is still accepted.
WATCHED = _cfg( "watched" , {} )

def _spec_macs( spec ):
	"""Raw MAC strings from a WATCHED value (dict or legacy bare list)."""
	if isinstance( spec , dict ):
		return list( spec.get( "macs" , () ) )
	return list( spec or () )

def _spec_names( key , spec ):
	"""Eero name strings to MATCH for a WATCHED value.

	When an explicit "names" list is given, those are matched EXACTLY — the
	device key is NOT auto-added. This is deliberate: the key is just our
	internal label, and it may collide with a DIFFERENT device's eero nickname
	(e.g. an always-on device someone nicknamed "Alex's iPhone" in the eero
	app that is not the real phone). Auto-injecting the key would re-match that
	imposter. With no "names" given we fall back to the key for convenience.
	"""
	if isinstance( spec , dict ) and "names" in spec:
		names = list( spec.get( "names" ) or () )
	else:
		names = [ key ]
	return list( dict.fromkeys( names ) )

def _sustain_max_for( name ):
	"""eero-sustain cap (minutes since last LAN hit) for this device. A WATCHED
	spec may override the global EERO_SUSTAIN_MAX_MIN with its own
	"eero_sustain_max_min" — for phones whose Wi-Fi deep-sleeps through LAN
	probes for long stretches while eero keeps reporting them connected."""
	spec = WATCHED.get( name )
	if isinstance( spec , dict ) and spec.get( "eero_sustain_max_min" ) is not None:
		return spec[ "eero_sustain_max_min" ]
	return EERO_SUSTAIN_MAX_MIN

# Per-device normalized MAC list (used for probe identity + state).
_DEVICE_MACS = { name: [ normalize_mac( m ) for m in _spec_macs( spec ) ]
                 for name , spec in WATCHED.items() }

def _macs_for( name ):
	return list( _DEVICE_MACS.get( name , () ) )

# Reverse lookups: normalized MAC -> device, normalized name-key -> device.
_MAC_TO_NAME = { mac: name for name , macs in _DEVICE_MACS.items() for mac in macs if mac }
_NAME_TO_DEVICE = { _norm_name( n ): name
                    for name , spec in WATCHED.items()
                    for n in _spec_names( name , spec ) }

def _device_for_eero_record( dev , runtime_mac_to_name=None ):
	"""Which watched device (if any) this eero record belongs to. Matches on
	any name field (display_name/nickname/hostname) first — robust to MAC
	rotation — then falls back to MAC.

	`runtime_mac_to_name` maps every private MAC we've previously seen this
	device use (learned at runtime and stored in last_known_macs) back to the
	device. Consulting it lets us keep attributing a phone after iOS rotates
	its Wi-Fi MAC, so eero's FRESH record for the new MAC is recognized instead
	of us clinging to the device's now-frozen old record. Those MACs were only
	ever learned via a prior name/MAC match, so they genuinely belong to it."""
	for field in ( "display_name" , "nickname" , "hostname" ):
		key = _norm_name( dev.get( field ) )
		# print( key , dev.get( "mac" ) )
		if key and key in _NAME_TO_DEVICE:
			return _NAME_TO_DEVICE[ key ]
	mac_n = normalize_mac( dev.get( "mac" ) )
	if mac_n and mac_n in _MAC_TO_NAME:
		return _MAC_TO_NAME[ mac_n ]
	if mac_n and runtime_mac_to_name and mac_n in runtime_mac_to_name:
		return runtime_mac_to_name[ mac_n ]
	return None

def _record_rank( dev ):
	"""Sort key for eero records of one device — most-current first:
	connected, then has-IP, then freshest last_active."""
	try:
		la = parse_eero_time( dev.get( "last_active" ) ).timestamp()
	except Exception:
		la = 0.0
	return ( 0 if dev.get( "connected" ) is True else 1 ,
	         0 if dev.get( "ipv4" ) else 1 ,
	         -la )

def _match_eero_records( name , eero_devices , runtime_mac_to_name=None ):
	"""All eero device records belonging to `name` (matched by MAC or name),
	deduped, most-current first."""
	out = []
	seen = set()
	for dev in eero_devices.values():
		if _device_for_eero_record( dev , runtime_mac_to_name ) != name:
			continue
		key = dev.get( "url" ) or normalize_mac( dev.get( "mac" ) ) or id( dev )
		if key in seen:
			continue
		seen.add( key )
		out.append( dev )
	out.sort( key=_record_rank )
	return out

# THIS INSTANCE only watches devices on this one eero network. LAN probes
# (arping/TCP/ping) only work for devices on the same subnet as the box
# running this script, so it doesn't make sense for one instance to track
# devices across multiple physically-separate networks. Run a separate
# instance of watch.py on a box in each network you want to monitor.
#
# Set to the exact 'name' of the eero network (the SSID, usually). Set to
# None to disable the filter and watch every network on the account (only
# useful if the watcher box can L2-reach all of them, which is rare).

# Local LAN interface name — needed for IPv6 link-local probes (e.g. ping6
# fe80::xxx%eth0). Auto-detected from the default route at startup; you can
# also hardcode it here ("eth0", "br0", "en0", "enp2s0", etc.).
def _detect_lan_interface():
	try:
		out = subprocess.run(
			[ "ip" , "route" , "get" , "1.1.1.1" ] ,
			capture_output=True , text=True , timeout=2 ,
		).stdout
		m = re.search( r"\bdev\s+(\S+)" , out )
		if m: return m.group( 1 )
	except Exception:
		pass
	try:
		out = subprocess.run(
			[ "route" , "-n" , "get" , "1.1.1.1" ] ,
			capture_output=True , text=True , timeout=2 ,
		).stdout
		m = re.search( r"interface:\s+(\S+)" , out )
		if m: return m.group( 1 )
	except Exception:
		pass
	return None

LAN_INTERFACE = _detect_lan_interface()


# ---------------------------------------------------------------------------
# State persistence (watch-specific)
# ---------------------------------------------------------------------------

def load_state():
	if not STATE_PATH.exists():
		return _fresh_state()
	try:
		with open( STATE_PATH , "r" ) as f:
			raw = json.load( f )
	except Exception as e:
		print( f"!! state file unreadable ({e}) — starting fresh" )
		return _fresh_state()

	old_devices = raw.get( "devices" , {} ) or {}
	new_devices = {}
	for name in WATCHED:
		# Prefer a name-keyed entry if present (current schema).
		if name in old_devices:
			d = old_devices[ name ]
		else:
			# Migrate: look through old MAC-keyed entries for ones belonging
			# to this device and pick the one with the most recent last_seen.
			candidates = []
			for mac in _macs_for( name ):
				if mac in old_devices:
					candidates.append( old_devices[ mac ] )
			if candidates:
				candidates.sort( key=lambda x: x.get( "last_seen" ) or "" , reverse=True )
				d = candidates[ 0 ]
			else:
				d = _fresh_device_state()
		# Fill in any new fields with defaults; strip obsolete legacy fields.
		for k , v in _fresh_device_state().items():
			d.setdefault( k , v )
		for obsolete in ( "name" , "home" , "arrived" , "arrived_at" , "left" ,
		                  "left_from" , "prev_eero_last_active" ,
		                  "absent_frozen_streak" ):
			d.pop( obsolete , None )
		# Older versions stored the first fe80:: from eero blindly — that can
		# be an eero bridge address (EUI-64 of the eero's own MAC), and probing
		# it phantom-confirms presence. Drop any stored v6 that is EUI-64 of a
		# MAC the device doesn't own.
		own_macs = as_mac_set( d.get( "last_known_macs" ) or d.get( "last_known_mac" ) )
		def _foreign_v6( a ):
			emb = eui64_embedded_mac( a or "" )
			return bool( emb and own_macs and emb not in own_macs )
		if _foreign_v6( d.get( "last_known_ipv6_link_local" ) ):
			d[ "last_known_ipv6_link_local" ] = None
		d[ "last_known_ipv6_link_locals" ] = [
			a for a in ( d.get( "last_known_ipv6_link_locals" ) or [] ) if not _foreign_v6( a )
		]
		# History vocabulary changed to "lan"/"eero"/"absent". Drop any legacy
		# ("present"/"absent") values rather than guess — mismapping a stale
		# "present" to "lan" could fake a LAN hit and arrive an away device.
		# Cleared once; refills within ARRIVE_WINDOW runs.
		if any( h not in ( "lan" , "eero" , "absent" ) for h in ( d.get( "history" ) or [] ) ):
			d[ "history" ] = []
		# Grace: a device that is currently HOME but has no last_lan_seen (first
		# run on the new schema) would otherwise be unsustainable and false-leave
		# before its next LAN hit. Seed last_lan_seen = now so it gets a normal
		# leave window to re-confirm on LAN (or leave naturally if truly gone).
		if d.get( "home_at" ) is not None and not d.get( "last_lan_seen" ):
			d[ "last_lan_seen" ] = to_iso( now_ny() )
		new_devices[ name ] = d

	raw[ "devices" ] = new_devices
	raw.setdefault( "events" , [] )
	return raw

def _fresh_state():
	return {
		"devices": { name: _fresh_device_state() for name in WATCHED } ,
		"events": [] ,
	}

def _fresh_device_state():
	return {
		"home_at": None ,                    # network name when home, else None
		"since": None ,                      # iso, when current state began
		"last_seen": None ,                  # iso, last run that VOUCHED (lan hit or valid eero-sustain)
		"last_lan_seen": None ,              # iso, last run a LAN probe actually answered
		"last_notified": None ,              # iso, last pushover send (any kind; info only)
		"notified_at": {} ,                  # { kind: iso } — per-type cooldown clock
		"last_known_ip": None ,              # IPv4 (freshest)
		"last_known_ips": [] ,               # every IPv4 eero reported, freshest first
		"last_known_ipv6_link_local": None , # fe80::... for v6 NDP probing
		"last_known_ipv6_link_locals": [] ,  # device-owned fe80::... (filtered)
		"last_known_network": None ,
		"last_known_mac": None ,             # best/freshest matched MAC (event log)
		"last_known_macs": [] ,              # every MAC eero showed for this device
		                                     # (rotated private Wi-Fi MACs) — probe
		                                     # identity-checks accept any of them
		"history": [] ,                      # last HISTORY_WINDOW runs, "lan"/"eero"/"absent"
	}

def save_state_atomic( state ):
	tmp = STATE_PATH.with_suffix( ".json.tmp" )
	with open( tmp , "w" ) as f:
		json.dump( state , f , indent=2 , sort_keys=True )
	tmp.replace( STATE_PATH )

def append_event( state , event ):
	"""Append a state-transition event and trim to MAX_EVENTS_KEPT."""
	state[ "events" ].append( event )
	if len( state[ "events" ] ) > MAX_EVENTS_KEPT:
		state[ "events" ] = state[ "events" ][ -MAX_EVENTS_KEPT: ]


# ---------------------------------------------------------------------------
# Eero fetch — across ALL networks on the account
# ---------------------------------------------------------------------------

def _prefer_new_device( new , old ):
	"""
	Tie-breaker when the same MAC appears on multiple eero networks.

	Order of preference:
	  1. The one currently 'connected: True' wins (it's actively associated).
	  2. The one with a current ipv4 wins (no IP = currently disconnected).
	  3. Freshest 'last_active' wins.
	  4. Otherwise keep the existing entry.
	"""
	nc , oc = new.get( "connected" ) , old.get( "connected" )
	if nc is True and oc is not True: return True
	if oc is True and nc is not True: return False

	new_has_ip = bool( new.get( "ipv4" ) )
	old_has_ip = bool( old.get( "ipv4" ) )
	if new_has_ip and not old_has_ip: return True
	if old_has_ip and not new_has_ip: return False

	try:
		new_la = parse_eero_time( new.get( "last_active" ) )
		old_la = parse_eero_time( old.get( "last_active" ) )
		return new_la > old_la
	except Exception:
		return False

def _resolve_networks( client ):
	"""
	account() lookup + MY_NETWORK filter. Returns ( nets , skipped_names ).

	Done ONCE per run, not once per probe — the network list doesn't change
	probe-to-probe, and the account() call is a full HTTP round trip.

	Honors MY_NETWORK: when set to a network name, only that network is
	kept. When None, every network on the account is kept (and the
	preference rule in _prefer_new_device picks the best entry per MAC).
	"""
	account = client.account()
	all_nets = account.get( "networks" , {} ).get( "data" , [] )

	if MY_NETWORK is not None:
		nets = [ n for n in all_nets if n.get( "name" ) == MY_NETWORK ]
		if not nets:
			available = [ n.get( "name" ) for n in all_nets ]
			raise RuntimeError(
				f"MY_NETWORK={MY_NETWORK!r} not found on this eero account. "
				f"Available networks: {available}"
			)
		skipped = [ n.get( "name" ) for n in all_nets if n.get( "name" ) != MY_NETWORK ]
	else:
		nets = all_nets
		skipped = []
	return ( nets , skipped )

def fetch_all_devices( client , nets , skipped=() , verbose=False ):
	"""
	Fetch devices from the given eero network(s) (from _resolve_networks).
	Returns { normalized_mac: device_dict } with '_network_name' /
	'_network_url' added to each device.
	"""
	if verbose:
		net_names = [ n.get( "name" , "?" ) for n in nets ]
		msg = f"[fetch] watching {net_names}"
		if skipped:
			msg += f" (skipping {skipped})"
		print( msg )

	result = {}
	per_net_counts = {}
	for net in nets:
		net_name = net.get( "name" , "?" )
		try:
			devices = client.devices( net[ "url" ] )
		except Exception as e:
			print( f"!! devices fetch failed for network '{net_name}': {e}" )
			continue
		per_net_counts[ net_name ] = len( devices )
		for d in devices:
			mac_n = normalize_mac( d.get( "mac" ) )
			if not mac_n:
				continue
			d[ "_network_name" ] = net_name
			d[ "_network_url" ] = net.get( "url" )
			existing = result.get( mac_n )
			if existing is None or _prefer_new_device( d , existing ):
				result[ mac_n ] = d

	if verbose:
		summary = ", ".join( f"{n}={c}" for n , c in per_net_counts.items() )
		print( f"[fetch] devices per network: {summary}" )
		for name in WATCHED:
			recs = _match_eero_records( name , result )
			if not recs:
				print( f"[fetch]   {name}: not present on '{MY_NETWORK or 'any network'}'" )
			else:
				best = recs[ 0 ]
				macs = ", ".join( normalize_mac( d.get( "mac" ) ) for d in recs )
				print( f"[fetch]   {name}: matched {len(recs)} record(s) [{macs}] on "
				       f"'{best.get( '_network_name' )}' connected={best.get( 'connected' )} "
				       f"display_name={best.get( 'display_name' )!r} last_active={best.get( 'last_active' )}" )
	return result


# ---------------------------------------------------------------------------
# Presence judgement
# ---------------------------------------------------------------------------

def judge_presence( eero_dev , stored_ips , macs , t_now , stored_ipv6s=None , iface=None ):
	"""
	Gather this run's two raw facts for the "LAN establishes, eero sustains"
	model (the state machine lives in run_once + decide_state_change):

	  lan_ok   — a live LAN probe answered (arping/TCP/ping/ping6, MAC-verified).
	             This is the ground truth for presence.
	  eero_conn — eero reports connected=True for the device. Used ONLY as a
	             sustain signal; never to establish presence (eero reports
	             phantom/edge associations for devices that aren't here).

	eero is otherwise just discovery: it supplies the IPs / link-locals to probe.

	Returns ( lan_ok , signals_dict ); signals carries lan_ok, eero_conn, the
	probe targets, the eero stats, and the LAN verdict for logging.
	"""
	sig = {}

	# Eero metadata — discovery (IPs/link-locals) + the connected flag + stats.
	eero_ip = None
	if eero_dev is not None:
		sig[ "network" ] = eero_dev.get( "_network_name" )
		eero_ip = eero_dev.get( "ipv4" )
		sig[ "eero_ip" ] = eero_ip
		try:
			la = parse_eero_time( eero_dev[ "last_active" ] )
			sig[ "eero_age_sec" ] = round( ( t_now - la ).total_seconds() , 1 )
			sig[ "eero_last_active" ] = to_iso( la )
		except Exception:
			sig[ "eero_last_active" ] = None
		# pull in connected, score, signal, rates, ipv6 link-locals, etc.
		sig.update( extract_eero_signals( eero_dev ) )

	eero_conn = ( sig.get( "eero_connected" ) is True )
	sig[ "eero_conn" ] = eero_conn

	# Probe targets: eero's freshest first, then any stored/discovered IPs.
	# Safe to merge because verify_on_lan MAC-checks every positive, so a stale
	# IP reassigned to another device can't phantom-confirm. Matters across a
	# DHCP move: eero's ipv4 lags, the kernel neigh-discovered IP is current.
	eero_ips = sig.get( "eero_ips" ) or ( [ eero_ip ] if eero_ip else [] )
	probe_ips = list( dict.fromkeys( eero_ips + list( stored_ips or [] ) ) )
	sig[ "probe_ips" ] = probe_ips
	sig[ "probe_ip" ] = probe_ips[ 0 ] if probe_ips else None

	probe_ipv6s = sig.get( "eero_ipv6_link_locals" ) or list( stored_ipv6s or [] )
	sig[ "probe_ipv6" ] = probe_ipv6s[ 0 ] if probe_ipv6s else None

	# --- The only presence ground truth: a live LAN probe. ---
	lan = "unknown"
	if ENABLE_LOCAL_PROBES and probe_ips:
		lan , lan_info = verify_on_lan( probe_ips , macs , ipv6_link_locals=probe_ipv6s , iface=iface )
		sig.update( lan_info )
		sig[ "lan_verdict" ] = lan
	else:
		sig[ "lan_verdict" ] = "skipped_no_ip" if not probe_ips else "skipped_disabled"

	lan_ok = ( lan == "reachable" )
	sig[ "lan_ok" ] = lan_ok
	return ( lan_ok , sig )


# ---------------------------------------------------------------------------
# Hysteresis
# ---------------------------------------------------------------------------

def decide_state_change( dev_state , signals , vouch , t_now ):
	"""
	"LAN establishes, eero sustains" transition logic — same for every device.
	`vouch` (computed in run_once) is True when this run had a LAN hit OR a valid
	eero-sustain (home + connected + last LAN hit still recent).

	Returns one of:
	  None                                          — no transition
	  {"kind": "arrived", "to":   <net>}            — AWAY -> HOME@net
	  {"kind": "left",    "from": <net>}            — HOME@net -> AWAY
	  {"kind": "moved",   "from": <X>, "to": <Y>}   — HOME@X -> HOME@Y

	Rules:
	  ARRIVED — >= CONSEC_TO_ARRIVE LAN hits within the last ARRIVE_WINDOW runs.
	            LAN only: eero can never arrive a device (history records "lan"
	            only on a real probe answer), which is what stops eero's phantom
	            associations (e.g. a spare phone or laptop) from faking arrivals.
	  LEFT    — no vouch for LEAVE_MINUTES (no LAN hit AND no valid eero-sustain),
	            measured from last_seen (the last vouching run).
	  MOVED   — eero places the device on a different network than home_at.
	"""
	home_at = dev_state.get( "home_at" )
	is_home = home_at is not None
	history = dev_state.get( "history" , [] )
	current_network = signals.get( "network" )

	# AWAY -> HOME — LAN establishes. Count real LAN hits in the recent window.
	if not is_home:
		lan_hits = sum( 1 for k in history[ -ARRIVE_WINDOW: ] if k == "lan" )
		if lan_hits >= CONSEC_TO_ARRIVE:
			landing = current_network or signals.get( "last_known_network" ) or MY_NETWORK
			return { "kind": "arrived" , "to": landing }
		return None

	# HOME@X -> HOME@Y — eero says it's on a different network (and it's vouched).
	if vouch and current_network and current_network != home_at:
		return { "kind": "moved" , "from": home_at , "to": current_network }

	# HOME -> AWAY — no vouch for LEAVE_MINUTES.
	last_seen = from_iso( dev_state.get( "last_seen" ) ) or from_iso( dev_state.get( "since" ) )
	if last_seen is not None and ( t_now - last_seen ).total_seconds() / 60.0 >= LEAVE_MINUTES:
		return { "kind": "left" , "from": home_at }
	return None


# ---------------------------------------------------------------------------
# Per-device pretty printer (for debugging why a device is/isn't "home")
# ---------------------------------------------------------------------------

def _probe_glyph( v ):
	"""Tri-state colored glyph: True -> green ✓, False -> red ✗, None -> dim —."""
	if v is True:    return "[green]✓[/]"
	if v is False:   return "[red]✗[/]"
	return "[dim]—[/]"

def _neigh_glyph( state ):
	"""Color the kernel neighbor state."""
	if not state:    return "[dim]—[/]"
	s = str( state ).lower()
	if s in ( "reachable" , "delay" , "probe" , "permanent" ):
		return f"[green]{s}[/]"
	if s == "failed":
		return f"[red]{s}[/]"
	return f"[yellow]{s}[/]"      # stale, unknown, etc

def _state_cell( home_at ):
	if home_at is None:
		return "[dim red]AWAY[/]"
	return "[bold green]HOME[/]"

def _change_cell( change ):
	if not isinstance( change , dict ):
		return "[dim]—[/]"
	kind = change[ "kind" ]
	if kind == "arrived":
		return f"[bold green]↑ ARRIVED[/] [dim]→ {change.get( 'to' ) or '?'}[/]"
	if kind == "left":
		return f"[bold red]↓ LEFT[/] [dim]from {change.get( 'from' ) or '?'}[/]"
	if kind == "moved":
		return f"[bold yellow]↔ MOVED[/] [dim]{change.get( 'from' )}→{change.get( 'to' )}[/]"
	return f"[yellow]{kind}[/]"

def _history_cell( history ):
	"""Colored last-10 runs, oldest-left newest-right: L=LAN hit (green),
	e=eero-sustained no LAN (yellow), _=absent (dim)."""
	glyph = { "lan": "[green]L[/]" , "eero": "[yellow]e[/]" }
	out = [ glyph.get( h , "[red dim]_[/]" ) for h in history[ -10: ] ]
	return "".join( out ) if out else "[dim]—[/]"

def _eero_cell( signals ):
	"""eero stats: connected flag + score + signal + active traffic."""
	if signals.get( "eero_age_sec" ) is None and "eero_connected" not in signals:
		return "[dim]—[/]"
	bits = []
	c = signals.get( "eero_connected" )
	if c is True:
		bits.append( "[green]C=Y[/]" )
	elif c is False:
		bits.append( "[red]C=N[/]" )
	if "eero_score" in signals:
		score = signals[ "eero_score" ]
		color = "green" if score >= 0.7 else ( "yellow" if score >= 0.3 else "red" )
		bits.append( f"[{color}]s={score}[/]" )
	if "eero_signal_dbm" in signals:
		bits.append( f"{signals[ 'eero_signal_dbm' ]}dBm" )
	if signals.get( "eero_active_traffic" ):
		bits.append( "[dim]rx/tx[/]" )
	return " ".join( bits ) if bits else "[dim]—[/]"

def render_status_table( device_views ):
	"""device_views is a list of dicts as built by build_device_view()."""
	t = Table(
		box=box.SIMPLE_HEAVY ,
		header_style="bold cyan" ,
		border_style="dim" ,
		padding=( 0 , 1 ) ,
		expand=False ,
	)
	t.add_column( "Device" , style="bold white" , no_wrap=True )
	t.add_column( "State" , justify="center" )
	t.add_column( "Net" , no_wrap=True )
	t.add_column( "Since" , justify="right" , no_wrap=True )
	t.add_column( "IPv4" , no_wrap=True )
	t.add_column( "Eero age" , justify="right" , no_wrap=True )
	t.add_column( "Eero stats" , no_wrap=True )
	t.add_column( "ARP" , justify="center" )
	t.add_column( "TCP" , justify="center" )
	t.add_column( "v6" , justify="center" )
	t.add_column( "ping" , justify="center" )
	t.add_column( "neigh" , justify="left" )
	t.add_column( "Verdict" , no_wrap=True )
	t.add_column( "Why" , no_wrap=True )
	t.add_column( "History" , no_wrap=True )
	t.add_column( "Change" , no_wrap=True )

	for v in device_views:
		t.add_row(
			v[ "name" ] ,
			v[ "state" ] ,
			v[ "network" ] ,
			v[ "since" ] ,
			v[ "ip" ] ,
			v[ "eero_age" ] ,
			v[ "eero_cell" ] ,
			v[ "arp" ] ,
			v[ "tcp" ] ,
			v[ "v6" ] ,
			v[ "ping" ] ,
			v[ "neigh" ] ,
			v[ "verdict" ] ,
			v[ "why" ] ,
			v[ "history" ] ,
			v[ "change" ] ,
		)
	_console.print( t )

def build_device_view( name , dev_state , run_result , signals , change , t_now ):
	"""Build the rendered cells (with Rich markup) for one device row."""
	home_at = dev_state[ "home_at" ]
	network = home_at or signals.get( "network" ) or dev_state.get( "last_known_network" ) or "[dim]—[/]"

	since_dt = from_iso( dev_state.get( "since" ) )
	since = humanize_duration( ( t_now - since_dt ).total_seconds() ) if since_dt else "[dim]—[/]"

	eero_age = humanize_duration( signals.get( "eero_age_sec" ) ) if signals.get( "eero_age_sec" ) is not None else "[dim]—[/]"
	ip = signals.get( "probe_ip" ) or dev_state.get( "last_known_ip" ) or "[dim]—[/]"
	extra_ips = len( signals.get( "probe_ips" ) or [] ) - 1
	if extra_ips > 0:
		ip = f"{ip} [dim]+{extra_ips}[/]"

	verdict = signals.get( "lan_verdict" , "—" )
	verdict_styled = {
		"reachable": "[green]reachable[/]" ,
		"absent":    "[red]absent[/]" ,
		"unknown":   "[yellow]unknown[/]" ,
	}.get( verdict , f"[dim]{verdict}[/]" )

	return {
		"name"      : name ,
		"state"     : _state_cell( home_at ) ,
		"network"   : network ,
		"since"     : since ,
		"ip"        : ip ,
		"eero_age"  : eero_age ,
		"eero_cell" : _eero_cell( signals ) ,
		"arp"       : _probe_glyph( signals.get( "arping" ) ) ,
		"tcp"       : _probe_glyph( signals.get( "tcp_62078" ) ) ,
		"v6"        : _probe_glyph( signals.get( "ipv6" ) ) ,
		"ping"      : _probe_glyph( signals.get( "ping" ) ) ,
		"neigh"     : _neigh_glyph( signals.get( "neigh_state" ) ) ,
		"verdict"   : verdict_styled ,
		"why"       : signals.get( "decision" , "[dim]?[/]" ) ,
		"history"   : _history_cell( dev_state.get( "history" , [] ) ) ,
		"change"    : _change_cell( change ) ,
	}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _probe_eero_with_retries():
	"""Returns (eero_devices_by_mac, eero_responded_bool)."""
	eero_devices = {}
	probe_errors = 0
	try:
		client = eero_pkg.Eero( CookieStore( COOKIE_PATH ) )
	except Exception as e:
		print( f"!! eero client init failed: {e}" )
		return ( {} , False )

	try:
		nets , skipped = _resolve_networks( client )
	except Exception as e:
		print( f"!! eero account/network lookup failed: {e}" )
		return ( {} , False )

	for i in range( PROBES_PER_RUN ):
		if i > 0:
			time.sleep( PROBE_DELAY_SEC )
		try:
			# verbose on the first probe so we get one diagnostic per run
			# (which networks, how many devices each, where each watched MAC landed)
			# verbose only when WATCH2_DEBUG is set, and only on the first probe
			probe = fetch_all_devices( client , nets , skipped , verbose=( _DEBUG and i == 0 ) )
		except Exception as e:
			probe_errors += 1
			print( f"!! eero probe {i+1}/{PROBES_PER_RUN} failed: {e}" )
			traceback.print_exc()
			continue
		# Merge respecting the same preference rule (active > stale)
		for mac_n , dev in probe.items():
			old = eero_devices.get( mac_n )
			if old is None or _prefer_new_device( dev , old ):
				eero_devices[ mac_n ] = dev
	return ( eero_devices , probe_errors < PROBES_PER_RUN )

def _apply_transition( dev_state , change , t_start , state , name , notices ):
	"""Mutate dev_state for the transition, log the event, fire notification."""
	kind = change[ "kind" ]
	if kind == "arrived":
		dev_state[ "home_at" ] = change[ "to" ]
		msg = f"{name} arrived home @ {change[ 'to' ] or '?'}"
	elif kind == "left":
		dev_state[ "home_at" ] = None
		# Clear rolling history so the pre-departure LAN hits can't immediately
		# re-trigger ARRIVE: coming back must be proven by FRESH LAN hits.
		dev_state[ "history" ] = []
		dev_state[ "last_lan_seen" ] = None
		msg = f"{name} left home @ {change[ 'from' ] or '?'}"
	elif kind == "moved":
		dev_state[ "home_at" ] = change[ "to" ]
		msg = f"{name} moved from {change[ 'from' ]} to {change[ 'to' ]}"
	else:
		msg = f"{name} state change: {kind}"
	dev_state[ "since" ] = to_iso( t_start )

	append_event( state , {
		"ts": to_iso( t_start ) ,
		"name": name ,
		"mac": dev_state.get( "last_known_mac" ) ,
		"kind": kind ,
		"from": change.get( "from" ) ,
		"to": change.get( "to" ) ,
	} )

	color = "green" if kind == "arrived" else ( "red" if kind == "left" else "yellow" )
	# Cooldown is PER DEVICE, PER KIND: an 'arrived' only suppresses a repeat
	# 'arrived', never a 'left'. So a genuine quick visit (arrive then leave a
	# few minutes later) fires BOTH; only same-type flapping within the window
	# (e.g. Wi-Fi toggling that re-triggers the same transition) is muted.
	notified_at = dev_state.setdefault( "notified_at" , {} )
	last_same = from_iso( notified_at.get( kind ) )
	cooldown = timedelta( minutes=NOTIFICATION_COOLDOWN_MIN )
	if last_same is not None and ( t_start - last_same ) < cooldown:
		notices.append( f"  [dim]⊘ {msg}  (suppressed — {NOTIFICATION_COOLDOWN_MIN}m {kind} cooldown)[/]" )
	else:
		send_notification( msg )
		notified_at[ kind ] = to_iso( t_start )
		dev_state[ "last_notified" ] = to_iso( t_start )
		notices.append( f"  [{color} bold]▶ {msg}[/]  [dim](pushover sent)[/]" )

def run_once():
	t_start = now_ny()
	_console.rule( f"[bold cyan]watch scan @ {fmt_dt_short( t_start )}[/]" , style="dim cyan" )

	state = load_state()
	eero_devices , eero_responded = _probe_eero_with_retries()

	rows = []
	notices = []

	# Runtime MAC -> device map: every private MAC we've previously seen each
	# device use (learned from earlier name/MAC matches and persisted in
	# last_known_macs). Lets eero records for a rotated MAC still attribute to
	# the device, so we read its FRESH record instead of clinging to the old
	# frozen one. Built once per run, before any matching.
	runtime_mac_to_name = {}
	for _name in WATCHED:
		_ds = state[ "devices" ][ _name ]
		for _m in ( as_mac_set( _ds.get( "last_known_macs" ) )
		            | as_mac_set( _ds.get( "last_known_mac" ) ) ):
			runtime_mac_to_name.setdefault( _m , _name )

	# Phase 1 (sequential, cheap): match eero entries, refresh discovery info.
	prepped = []
	for name in WATCHED:
		dev_state = state[ "devices" ][ name ]

		# Match EVERY eero record for this device — by configured name(s) or
		# MAC. iPhones report inconsistent display_names and rotate private
		# Wi-Fi MACs, so a device can appear under several records; we
		# aggregate the IPs and link-locals across all of them and probe union.
		records = _match_eero_records( name , eero_devices , runtime_mac_to_name )
		eero_dev = records[ 0 ] if records else None   # most-current, for signals

		# Aggregate addresses + MACs across all matched records (most-current
		# first, since records is already sorted that way).
		agg_ips , agg_v6s , agg_macs = [] , [] , []
		for d in records:
			for ip in extract_eero_ips( d ):
				if ip not in agg_ips: agg_ips.append( ip )
			for a in extract_device_ipv6_link_locals( d ):
				if a not in agg_v6s: agg_v6s.append( a )
			dm = normalize_mac( d.get( "mac" ) )
			if dm and dm not in agg_macs: agg_macs.append( dm )

		# capture/refresh per-device discovery info whenever eero shows it
		if eero_dev is not None:
			if eero_dev.get( "ipv4" ):
				dev_state[ "last_known_ip" ] = eero_dev[ "ipv4" ]
			if agg_ips:
				# eero's freshest first, then recent/discovered stragglers —
				# keeps the previous IP probeable across a DHCP move (probes
				# are MAC-verified, so stale entries are safe). Capped small.
				merged = agg_ips + [ ip for ip in ( dev_state.get( "last_known_ips" ) or [] ) if ip not in agg_ips ]
				dev_state[ "last_known_ips" ] = merged[ :6 ]
			if eero_dev.get( "_network_name" ):
				dev_state[ "last_known_network" ] = eero_dev[ "_network_name" ]
			if agg_macs:
				dev_state[ "last_known_mac" ] = agg_macs[ 0 ]
				# union configured + freshly-seen MACs (rotated private MACs)
				known = agg_macs + [ m for m in ( dev_state.get( "last_known_macs" ) or [] ) if m not in agg_macs ]
				dev_state[ "last_known_macs" ] = known[ :8 ]
			# device-owned link-locals only — eero mixes its own bridge
			# addresses into ipv6_addresses (see extract_device_ipv6_link_locals)
			if agg_v6s:
				dev_state[ "last_known_ipv6_link_locals" ] = agg_v6s
				dev_state[ "last_known_ipv6_link_local" ] = agg_v6s[ 0 ]

		# Probe identity = configured MACs + every MAC eero/state has seen for
		# this device, so a reply from any rotated MAC still counts.
		probe_macs = list( as_mac_set( _macs_for( name ) )
		                   | as_mac_set( dev_state.get( "last_known_macs" ) )
		                   | as_mac_set( dev_state.get( "last_known_mac" ) ) )
		prepped.append( ( name , dev_state , eero_dev , probe_macs ) )

	# Phase 2 (parallel): probe every device at once. judge_presence is
	# dominated by subprocess/socket timeouts (an absent device eats the full
	# arping+TCP+ping6+ping chain, ~18s), so threading turns the LAN phase
	# from sum-of-devices into max-of-devices. No shared state is mutated here.
	def _judge( p ):
		name , dev_state , eero_dev , probe_macs = p
		stored_ips = dev_state.get( "last_known_ips" ) or \
		             ( [ dev_state[ "last_known_ip" ] ] if dev_state.get( "last_known_ip" ) else [] )
		stored_v6s = dev_state.get( "last_known_ipv6_link_locals" ) or \
		             ( [ dev_state[ "last_known_ipv6_link_local" ] ] if dev_state.get( "last_known_ipv6_link_local" ) else [] )
		return judge_presence(
			eero_dev , stored_ips , probe_macs , t_start ,
			stored_ipv6s=stored_v6s , iface=LAN_INTERFACE ,
		)

	with ThreadPoolExecutor( max_workers=max( len( prepped ) , 1 ) ) as pool:
		judgements = list( pool.map( _judge , prepped ) )

	# Phase 3 (sequential): state updates, transitions, notifications, render.
	for ( name , dev_state , eero_dev , probe_macs ) , ( lan_ok , signals ) in zip( prepped , judgements ):
		signals[ "last_known_network" ] = dev_state.get( "last_known_network" )

		# Adopt the kernel-discovered IPv4 for this device as a probe target.
		# After a DHCP move the neigh table learns the new IP from the device's
		# own broadcasts long before eero's cloud record catches up.
		neigh_v4 = signals.get( "neigh_ipv4" )
		if neigh_v4 and neigh_v4 not in ( dev_state.get( "last_known_ips" ) or [] ):
			dev_state[ "last_known_ips" ] = ( [ neigh_v4 ] + ( dev_state.get( "last_known_ips" ) or [] ) )[ :6 ]

		# --- "LAN establishes, eero sustains" per-run bookkeeping ---
		is_home = dev_state[ "home_at" ] is not None
		eero_conn = signals.get( "eero_conn" , False )
		if lan_ok:
			dev_state[ "last_lan_seen" ] = to_iso( t_start )
		last_lan = from_iso( dev_state.get( "last_lan_seen" ) )
		lan_recent = last_lan is not None and \
		             ( t_start - last_lan ).total_seconds() / 60.0 < _sustain_max_for( name )
		# eero may sustain an already-home device, but only while a LAN hit is
		# still recent — a device that never answers LAN can't be sustained.
		sustain = is_home and eero_conn and lan_recent
		vouch = lan_ok or sustain
		run_kind = "lan" if lan_ok else ( "eero" if sustain else "absent" )
		signals[ "sustain" ] = sustain
		signals[ "decision" ] = { "lan": "lan_present" , "eero": "eero_sustain" ,
		                          "absent": ( "eero_conn_no_lan" if eero_conn else "absent" ) }[ run_kind ]

		# update rolling history
		dev_state[ "history" ].append( run_kind )
		if len( dev_state[ "history" ] ) > HISTORY_WINDOW:
			dev_state[ "history" ] = dev_state[ "history" ][ -HISTORY_WINDOW: ]
		if vouch:
			dev_state[ "last_seen" ] = to_iso( t_start )

		change = decide_state_change( dev_state , signals , vouch , t_start )
		if change is not None:
			_apply_transition( dev_state , change , t_start , state , name , notices )

		rows.append( build_device_view( name , dev_state , run_kind , signals , change , t_start ) )

	_console.print()
	render_status_table( rows )
	_console.print()

	# Per-target probe detail — shows that every IP/addr was tested every scan
	# (no early-exit) and exactly which probe answered on which address.
	detail_lines = []
	for ( name , dev_state , eero_dev , probe_macs ) , ( lan_ok , signals ) in zip( prepped , judgements ):
		pd = signals.get( "probe_detail" )
		if not pd:
			continue
		cells = [ f"{k}={'✓' if v is True else ('·' if v is None else '✗')}" for k , v in pd.items() ]
		detail_lines.append( f"  [dim]{name}: " + "  ".join( cells ) + "[/]" )
	if detail_lines:
		_console.print( "[bold cyan]Probe detail (all targets, every scan):[/]" )
		for ln in detail_lines:
			_console.print( ln )
		_console.print()

	if notices:
		_console.print( "[bold cyan]State changes:[/]" )
		for n in notices:
			_console.print( n )
		_console.print()

	save_state_atomic( state )
	elapsed = ( now_ny() - t_start ).total_seconds()
	_console.rule( f"[dim]done in {elapsed:.1f}s[/]" , style="dim cyan" )
	_console.print()


if __name__ == "__main__":
	run_once()
