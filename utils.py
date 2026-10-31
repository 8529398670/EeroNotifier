#!/usr/bin/env python
"""
utils.py — shared helpers used by watch2.py (and any future scripts in this repo).

Contains: timezone-aware time helpers, MAC normalization, eero session cookie
storage, pushover notifier, and local-network probes (ping + ARP + Linux
`ip neigh`).
"""

import errno
import json
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor , as_completed
from datetime import datetime , timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
import eero as eero_pkg

from config import get as _cfg


# ---------------------------------------------------------------------------
# Platform / timezone
# ---------------------------------------------------------------------------

NY = ZoneInfo( "America/New_York" )
UTC = timezone.utc
IS_LINUX = ( platform.system() == "Linux" )


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def now_ny():
	return datetime.now( NY )

def parse_eero_time( timestr ):
	"""Eero returns e.g. '2025-05-21T14:30:21.123Z'."""
	dt_utc = datetime.strptime( timestr , "%Y-%m-%dT%H:%M:%S.%fZ" ).replace( tzinfo=UTC )
	return dt_utc.astimezone( NY )

def fmt_dt( dt ):
	if dt is None:
		return None
	ms = str( round( dt.microsecond / 1000 ) ).zfill( 3 )
	return f"{dt.strftime( '%d%b%Y === %H:%M:%S' ).upper()}.{ms}"

def to_iso( dt ):
	return None if dt is None else dt.isoformat()

def from_iso( s ):
	return None if s is None else datetime.fromisoformat( s )

def humanize_duration( seconds ):
	"""
	Compact human-readable duration. Examples:
	  45        -> '45s'
	  276       -> '4m 36s'
	  4523      -> '1h 15m'
	  90061     -> '1d 1h'
	  None      -> '-'
	"""
	if seconds is None:
		return "-"
	try:
		seconds = int( seconds )
	except ( ValueError , TypeError ):
		return "-"
	sign = "-" if seconds < 0 else ""
	seconds = abs( seconds )
	if seconds < 60:
		return f"{sign}{seconds}s"
	if seconds < 3600:
		m , s = divmod( seconds , 60 )
		return f"{sign}{m}m {s}s"
	if seconds < 86400:
		h , rem = divmod( seconds , 3600 )
		m = rem // 60
		return f"{sign}{h}h {m}m"
	d , rem = divmod( seconds , 86400 )
	h = rem // 3600
	return f"{sign}{d}d {h}h"

def fmt_dt_short( dt ):
	"""Short datetime for tables: '21May 12:23:00'. Returns '-' for None."""
	if dt is None:
		return "-"
	return dt.strftime( "%d%b %H:%M:%S" )


# ---------------------------------------------------------------------------
# ASCII table rendering
# ---------------------------------------------------------------------------

def render_table( rows , columns ):
	"""
	Render a simple ASCII table.
	  rows    : list of dicts
	  columns : list of ( key , header ) tuples (preserves order)
	Returns the rendered string.
	"""
	widths = {}
	for key , header in columns:
		widths[ key ] = len( header )
		for row in rows:
			widths[ key ] = max( widths[ key ] , len( str( row.get( key , "" ) ) ) )

	def fmt( row ):
		return "  ".join( str( row.get( k , "-" ) ).ljust( widths[ k ] ) for k , _ in columns )

	header_row = { k: h for k , h in columns }
	sep_row = { k: "─" * widths[ k ] for k , _ in columns }
	return "\n".join( [ fmt( header_row ) , fmt( sep_row ) ] + [ fmt( r ) for r in rows ] )


# ---------------------------------------------------------------------------
# MAC normalization
# ---------------------------------------------------------------------------

# IPv4 dotted-quad — the eero `ips` list can mix in IPv6 strings
_IPV4_RE = re.compile( r"^\d{1,3}(\.\d{1,3}){3}$" )

# eero's own bridge interfaces — `ipv6_addresses` on a device record sometimes
# contains the EERO'S bridge link-locals, not the client's. Probing those gets
# an answer from the eero itself -> every device looks present forever.
_EERO_BRIDGE_IFACES = { "br_lan" , "br_wan" , "br_guest" }

def eui64_embedded_mac( fe80_addr ):
	"""
	If a link-local was built via EUI-64 (the ff:fe marker in the middle of the
	interface id), recover the MAC that generated it. Returns a normalized MAC,
	or None when the address isn't EUI-64 (e.g. iOS privacy addresses).
	"""
	try:
		packed = socket.inet_pton( socket.AF_INET6 , fe80_addr )
	except ( OSError , ValueError ):
		return None
	iid = packed[ 8: ]
	if iid[ 3 ] != 0xFF or iid[ 4 ] != 0xFE:
		return None
	mac_bytes = bytes( [ iid[ 0 ] ^ 0x02 ] ) + iid[ 1:3 ] + iid[ 5:8 ]
	return normalize_mac( ":".join( f"{b:02x}" for b in mac_bytes ) )

def extract_device_ipv6_link_locals( device ):
	"""
	The device's OWN fe80:: link-locals from an eero record. Keep an address
	only if it's not on an eero bridge interface AND it's either non-EUI-64
	(iOS privacy style) or EUI-64 of the device's own MAC — anything else is
	some other host's address (usually the eero's) and must not be probed.
	"""
	out = []
	if not device:
		return out
	dev_mac = normalize_mac( device.get( "mac" ) or "" )
	for addr in ( device.get( "ipv6_addresses" ) or [] ):
		if not isinstance( addr , dict ) or addr.get( "scope" ) != "link":
			continue
		if ( addr.get( "interface" ) or "" ).lower() in _EERO_BRIDGE_IFACES:
			continue
		a = ( addr.get( "address" ) or "" ).split( "/" )[ 0 ]
		if not a.lower().startswith( "fe80" ):
			continue
		embedded = eui64_embedded_mac( a )
		if embedded and dev_mac and embedded != dev_mac:
			continue
		if a not in out:
			out.append( a )
	return out

def extract_eero_ips( device ):
	"""
	Every IPv4 eero reports for a device (`ipv4` + the `ips` list), deduped,
	freshest (`ipv4`) first. Multi-homed clients / devices behind repeaters can
	hold several at once.
	"""
	out = []
	if not device:
		return out
	for ip in [ device.get( "ipv4" ) ] + list( device.get( "ips" ) or [] ):
		if ip and _IPV4_RE.match( str( ip ) ) and ip not in out:
			out.append( ip )
	return out

def extract_eero_signals( device ):
	"""
	Pull every useful field from the eero device dict into a flat signals dict.
	All fields are best-effort; missing/malformed values are skipped.

	The 'connected' + 'has_ip' pair is the key departure signal — both flip
	together when eero processes a deauth, and unlike connectivity stats they
	don't go stale (stats stay frozen at their last value forever, while these
	reset to False/None within seconds of disconnection).

	Returns keys (when available):
	  eero_connected      (bool)            — eero's association state for the device
	  eero_has_ip         (bool)            — does eero currently report an ipv4
	  eero_score          (float 0.0-1.0)   — eero's own connection quality score
	  eero_score_bars     (int 0-5)         — same, bucketed for display
	  eero_signal_dbm     (int, e.g. -45)   — RSSI in dBm
	  eero_frequency_mhz  (float)           — 2412 / 5180 / etc.
	  eero_rx_bitrate     (float, Mbps)     — last-seen receive bitrate
	  eero_rx_rate_bps    (int or None)     — current rx rate; None means quiet
	  eero_tx_rate_bps    (int or None)     — current tx rate; None means quiet
	  eero_source         (str)             — which eero AP the device is on
	  eero_active_traffic (bool)            — true if rx or tx rate is non-zero
	"""
	if device is None:
		return {}
	sig = {}

	# Association state (smoking-gun signals for departure)
	if "connected" in device:
		sig[ "eero_connected" ] = bool( device[ "connected" ] )
	sig[ "eero_has_ip" ] = bool( device.get( "ipv4" ) )

	# IPv6 link-locals — a second L3 stack to probe (iOS often responds to
	# IPv6 NDP when IPv4 ARP misses, since the stacks are independent in the
	# OS). Filtered to the device's OWN addresses — see
	# extract_device_ipv6_link_locals for why blind use is dangerous.
	v6s = extract_device_ipv6_link_locals( device )
	if v6s:
		sig[ "eero_ipv6_link_locals" ] = v6s
		sig[ "eero_ipv6_link_local" ] = v6s[ 0 ]

	# Every IPv4 eero currently knows for the device
	all_ips = extract_eero_ips( device )
	if all_ips:
		sig[ "eero_ips" ] = all_ips

	conn = device.get( "connectivity" ) or {}

	def _safe_float( x ):
		try:    return float( str( x ).split( " " )[ 0 ] )
		except: return None
	def _safe_int( x ):
		try:    return int( float( str( x ).split( " " )[ 0 ] ) )
		except: return None

	s = _safe_float( conn.get( "score" ) )
	if s is not None: sig[ "eero_score" ] = round( s , 3 )
	sb = _safe_int( conn.get( "score_bars" ) )
	if sb is not None: sig[ "eero_score_bars" ] = sb
	sd = _safe_int( conn.get( "signal" ) )
	if sd is not None: sig[ "eero_signal_dbm" ] = sd
	fq = _safe_float( conn.get( "frequency" ) )
	if fq is not None: sig[ "eero_frequency_mhz" ] = fq
	rxb = _safe_float( conn.get( "rx_bitrate" ) )
	if rxb is not None: sig[ "eero_rx_bitrate" ] = rxb

	rx = ( conn.get( "rx_rate_info" ) or {} ).get( "rate_bps" )
	tx = ( conn.get( "tx_rate_info" ) or {} ).get( "rate_bps" )
	sig[ "eero_rx_rate_bps" ] = rx
	sig[ "eero_tx_rate_bps" ] = tx
	sig[ "eero_active_traffic" ] = bool( rx or tx )

	src = device.get( "source" )
	if isinstance( src , dict ) and src.get( "display_name" ):
		sig[ "eero_source" ] = src[ "display_name" ]

	return sig

def normalize_mac( mac ):
	"""
	Lowercase, pad each octet to 2 hex chars. macOS arp output drops leading
	zeros (e.g. '0:1:22:...' for '00:01:22:...'), so we normalize both sides
	before comparing.
	"""
	if mac is None:
		return None
	parts = str( mac ).strip().lower().split( ":" )
	if len( parts ) != 6:
		return mac.lower()
	return ":".join( p.zfill( 2 ) for p in parts )


# ---------------------------------------------------------------------------
# Eero session
# ---------------------------------------------------------------------------

class CookieStore( eero_pkg.SessionStorage ):
	"""
	Flat-file eero session cookie. Strips whitespace on both read and write —
	urllib3 rejects header values containing '\\n', and editors love to add one.
	"""
	def __init__( self , cookie_file ):
		from os import path
		self.cookie_file = path.abspath( cookie_file )
		try:
			with open( self.cookie_file , "r" ) as f:
				raw = f.read().strip()
			self.__cookie = raw if raw else None
		except IOError:
			self.__cookie = None

	@property
	def cookie( self ):
		return self.__cookie

	@cookie.setter
	def cookie( self , cookie ):
		cookie = ( cookie or "" ).strip()
		self.__cookie = cookie
		with open( self.cookie_file , "w+" ) as f:
			f.write( self.__cookie )


# ---------------------------------------------------------------------------
# Pushover notifications
# ---------------------------------------------------------------------------

PUSHOVER_TOKEN = _cfg( "pushover.token" )
PUSHOVER_USER = _cfg( "pushover.user" )
PUSHOVER_SOUND = _cfg( "pushover.sound" , "NES-Zelda-Secret" )

def send_notification( message , sound=PUSHOVER_SOUND ):
	print( f">> NOTIFY: {message}" )
	try:
		r = requests.post(
			"https://api.pushover.net/1/messages.json" ,
			data={
				"token": PUSHOVER_TOKEN ,
				"user": PUSHOVER_USER ,
				"sound": sound ,
				"message": message ,
			} ,
			timeout=10 ,
		)
		r.raise_for_status()
	except Exception as e:
		print( f"!! pushover failed: {e}" )


# ---------------------------------------------------------------------------
# Local network probes
# ---------------------------------------------------------------------------

def as_mac_set( macs ):
	"""
	Normalize a MAC, a list of MACs, or None into a set of normalized MACs
	(empty falsy values dropped). iPhones rotate private Wi-Fi MACs, so a
	device legitimately answers from any of several addresses — every probe
	identity-check works against this SET, not a single MAC.
	"""
	if macs is None:
		return set()
	if isinstance( macs , str ):
		macs = [ macs ]
	return { normalize_mac( m ) for m in macs if m }

# Standard ICMP ping (timing in config.yaml -> probe_timing)
PING_TIMEOUT_MS = _cfg( "probe_timing.ping_timeout_ms" , 1000 )
PING_COUNT = _cfg( "probe_timing.ping_count" , 3 )   # multi-packet to hit iOS Wi-Fi sleep wake windows

# arping config — aggressive for catching sleepy iPhones.
# Multi-packet because iOS Wi-Fi power save means the phone wakes only at
# DTIM intervals (~300ms to several seconds). 10 packets over 10 seconds
# means we cover many wake windows. The `-f` flag makes arping exit on the
# FIRST reply — so present devices return in ~500ms; absent devices wait
# the full 10s. Net: more wake-coverage AND faster for the common case.
ARPING_COUNT = _cfg( "probe_timing.arping_count" , 10 )
ARPING_TIMEOUT_SEC = _cfg( "probe_timing.arping_timeout_sec" , 10 )

# TCP probe — fallback when arping misses. Port 62078 is the iOS Lockdown
# service, listening on every iPhone connected to Wi-Fi. A SYN there gets
# either SYN-ACK (connected) or RST (refused) — either way the host is alive.
#
# Multi-attempt for the SAME reason arping is multi-packet: a deep-power-save
# iPhone (ignores broadcast ARP and ICMP entirely, only its unicast TCP stack
# answers when it briefly wakes at a DTIM interval) is reachable only during
# narrow wake windows. One SYN per scan catches it ~half the time ("every
# other scan"); several spaced SYNs sample multiple wake windows and catch it
# almost every scan. Total worst-case time (4*2s + 3*0.4s ≈ 9.2s) stays under
# the arping ceiling, and they run concurrently, so this adds no wall time.
TCP_PROBE_PORT = _cfg( "probe_timing.tcp_probe_port" , 62078 )
TCP_PROBE_TIMEOUT_SEC = _cfg( "probe_timing.tcp_probe_timeout_sec" , 2 )     # per attempt
TCP_PROBE_ATTEMPTS = _cfg( "probe_timing.tcp_probe_attempts" , 4 )
TCP_PROBE_GAP_SEC = _cfg( "probe_timing.tcp_probe_gap_sec" , 0.4 )       # spacing between attempts, to span different wakes

ARP_BIN = _cfg( "probe_timing.arp_bin" , "/usr/sbin/arp" )
ENABLE_LOCAL_PROBES = _cfg( "probing.enable_local_probes" , True )   # callers can flip this off if not on the LAN

FRESH_NEIGH_STATES = { "reachable" , "delay" , "probe" , "permanent" }

_ARP_LINE_RE = re.compile( r"\(([\d\.]+)\)\s+at\s+([0-9a-fA-F:]+)" )

# iputils arping reply line: "Unicast reply from 192.168.1.50 [AA:BB:CC:DD:EE:FF]  0.19ms"
_ARPING_REPLY_MAC_RE = re.compile( r"reply from [\d\.]+\s+\[([0-9A-Fa-f:]+)\]" )

def arping_once( ip , count=ARPING_COUNT , timeout_sec=ARPING_TIMEOUT_SEC , expect_macs=None ):
	"""
	Multi-packet L2 ARP probe. Returns:
	  True  — got an ARP reply (device confirmed on LAN)
	  False — sent all packets, got no reply within timeout
	  None  — arping binary not installed or not permitted

	When expect_macs is given (a MAC or set of MACs), a reply only counts if it
	came FROM one of those MACs. This makes probing old/possibly-stale IPs
	safe: if DHCP handed the IP to a different device, its replies are ignored
	instead of phantom-confirming the device we're looking for. A device with
	several rotated private MACs answers from any of them and still counts.

	Multi-packet because iOS Wi-Fi power save means the phone wakes briefly at
	DTIM intervals; a single ARP can miss the wake window. arping exits on
	first reply so present devices return fast.

	Requires `arping` (iputils-arping on Debian/Ubuntu). Usually has
	CAP_NET_RAW set on the binary so it works as non-root; if not:
	  sudo setcap cap_net_raw=ep $(which arping)
	In Docker, container needs --cap-add=NET_RAW.
	"""
	if not ENABLE_LOCAL_PROBES or not ip:
		return False
	want = as_mac_set( expect_macs )
	try:
		r = subprocess.run(
			# -f = finish on first reply (key for fast present-device detection)
			[ "arping" , "-c" , str( count ) , "-w" , str( timeout_sec ) , "-f" , ip ] ,
			capture_output=True , text=True , timeout=timeout_sec + 2 ,
		)
		if r.returncode != 0:
			return False
		if want:
			replied = { normalize_mac( m ) for m in _ARPING_REPLY_MAC_RE.findall( r.stdout ) }
			if replied and not ( replied & want ):
				return False  # the IP answered, but it isn't our device anymore
		return True
	except FileNotFoundError:
		return None  # arping not installed — caller can fall back
	except Exception:
		return False

def ping6_once( ipv6_link_local , iface , count=3 , timeout_sec=3 ):
	"""
	ICMPv6 probe of a link-local address. Returns True/False on reply.
	Link-local IPv6 requires the interface scope: 'fe80::xxx%iface'.

	iOS maintains an IPv6 stack independent of IPv4 — sometimes it answers
	NDP/ICMPv6 when ARP/ICMPv4 misses (different code paths inside the OS).
	Cheap second-opinion probe.
	"""
	if not ENABLE_LOCAL_PROBES or not ipv6_link_local or not iface:
		return False
	target = f"{ipv6_link_local}%{iface}" if "%" not in ipv6_link_local else ipv6_link_local
	# 'ping -6' works on both Linux and macOS; 'ping6' also works on both.
	cmd = [ "ping" , "-6" , "-c" , str( count ) , "-W" , "1" , target ] if IS_LINUX else \
	      [ "ping6" , "-c" , str( count ) , target ]
	try:
		r = subprocess.run(
			cmd , capture_output=True , text=True , timeout=timeout_sec + 2 ,
		)
		return r.returncode == 0
	except FileNotFoundError:
		return False
	except Exception:
		return False

def tcp_probe( ip , port=TCP_PROBE_PORT , timeout=TCP_PROBE_TIMEOUT_SEC ,
              attempts=TCP_PROBE_ATTEMPTS , gap=TCP_PROBE_GAP_SEC ):
	"""
	Multi-attempt TCP SYN probe. Returns True if the device responds on ANY
	attempt (either accepts the connection or refuses it — both prove the host
	is alive), False if every attempt times out.

	Default port 62078 = iOS Lockdown service, listening on every iPhone on
	Wi-Fi. Useful as a second-opinion when arping misses: unicast TCP can wake
	a sleeping phone via a different code path than broadcast ARP. Retried
	across several spaced attempts to catch a power-save phone's narrow wake
	windows (see the TCP_PROBE_* constants).

	connect_ex return codes:
	  0                = connected (SYN-ACK received, device alive)
	  ECONNREFUSED     = device sent RST (alive, port closed)
	  ETIMEDOUT / etc. = no reply (asleep, gone, or firewalled)
	"""
	if not ENABLE_LOCAL_PROBES or not ip:
		return False
	for i in range( max( 1 , attempts ) ):
		try:
			s = socket.socket( socket.AF_INET , socket.SOCK_STREAM )
			s.settimeout( timeout )
			result = s.connect_ex( ( ip , port ) )
			s.close()
			if result == 0 or result == errno.ECONNREFUSED:
				return True
		except Exception:
			pass
		if i < attempts - 1:
			time.sleep( gap )
	return False

def ping_once( ip , count=PING_COUNT ):
	"""
	Multi-packet ICMP ping. Returns True if any packet got a reply.
	Side effect (intentional): populates the local L2 cache regardless of
	whether ICMP itself succeeds — iPhone Wi-Fi chips reply to ARP probes
	even when ICMP is dropped.

	macOS BSD ping: -W is milliseconds.
	Linux iputils ping: -W is seconds. Adapt per OS.
	"""
	if not ENABLE_LOCAL_PROBES or not ip:
		return False
	wait_arg = str( max( 1 , PING_TIMEOUT_MS // 1000 ) ) if IS_LINUX else str( PING_TIMEOUT_MS )
	timeout_total = ( count * 2 ) + 2
	try:
		r = subprocess.run(
			[ "ping" , "-c" , str( count ) , "-W" , wait_arg , ip ] ,
			capture_output=True , text=True , timeout=timeout_total ,
		)
		return r.returncode == 0
	except Exception:
		return False

# UDP "nudge" to coax a power-saving iPhone's Wi-Fi chip awake. A deep-sleep
# iPhone ignores ICMP and (after ~30s) even ARP requests, but its chip still
# processes INBOUND traffic to a listened UDP port — mDNS/5353 is always
# listened. Firing a few datagrams there briefly wakes the chip and triggers the
# kernel's ARP resolution, so the arping/TCP battery (and the neigh table) can
# then see it. Standard iPhone-presence trick; fire-and-forget (not a verdict).
UDP_NUDGE_PORTS = ( 5353 , )
# A well-formed mDNS query ("_services._dns-sd._udp.local" PTR) — any inbound UDP
# wakes the chip, and a valid query also has a chance of drawing a response.
_MDNS_QUERY = ( b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01" )

def udp_nudge( ip , ports=UDP_NUDGE_PORTS , count=4 , gap=0.15 ):
	"""Fire a few UDP datagrams at the device to wake its Wi-Fi chip. Returns
	None — it provokes, it does not judge (the follow-up arping/TCP/neigh do)."""
	if not ENABLE_LOCAL_PROBES or not ip:
		return None
	for p in ports:
		try:
			s = socket.socket( socket.AF_INET , socket.SOCK_DGRAM )
			for _ in range( max( 1 , count ) ):
				s.sendto( _MDNS_QUERY , ( ip , p ) )
				time.sleep( gap )
			s.close()
		except Exception:
			pass
	return None

def read_arp_table():
	"""
	macOS/BSD `arp -an` cache. Returns { normalized_mac: ip }.
	Stale entries persist ~20min after a device leaves — treat as weak/diagnostic
	info only. On Linux prefer read_linux_neigh_table() which exposes per-entry
	state.
	"""
	if not ENABLE_LOCAL_PROBES:
		return {}
	cmd = [ ARP_BIN , "-an" ] if Path( ARP_BIN ).exists() else [ "arp" , "-an" ]
	try:
		out = subprocess.run( cmd , capture_output=True , text=True , timeout=5 ).stdout
	except Exception as e:
		print( f"!! arp lookup failed: {e}" )
		return {}
	result = {}
	for line in out.splitlines():
		m = _ARP_LINE_RE.search( line )
		if not m:
			continue
		mac = normalize_mac( m.group( 2 ) )
		if mac == "incomplete":
			continue
		result[ mac ] = m.group( 1 )
	return result

def _fanout_all( tasks ):
	"""
	Run EVERY ( key , fn ) task in parallel threads and return { key: result }.
	No early exit — every probe completes, so each scan exercises all of them
	(arping + TCP + ping per IP, ping6 per link-local). Wall time is the single
	slowest probe's timeout, not the sum, since they all run concurrently.
	"""
	results = {}
	if not tasks:
		return results
	pool = ThreadPoolExecutor( max_workers=len( tasks ) )
	try:
		futs = { pool.submit( fn ): key for key , fn in tasks }
		for f in as_completed( futs ):
			results[ futs[ f ] ] = f.result()
	finally:
		pool.shutdown( wait=False )
	return results

def _agg_probe( results ):
	"""
	Collapse per-target probe results into one tri-state for display/verdicts:
	True if any target answered; None if nothing actually ran (no targets, or
	probe binary unavailable for all); False if probes ran and all came back
	negative.
	"""
	vals = list( results.values() )
	if any( v is True for v in vals ):
		return True
	if not vals or all( v is None for v in vals ):
		return None
	return False

def verify_on_lan( ips , macs , ipv6_link_locals=None , iface=None ):
	"""
	Active local-network verification, layering multiple probes so a sleeping
	iPhone has many chances to respond.

	`ips` / `ipv6_link_locals` accept a single address or a list — a device can
	hold several IPv4s (repeaters, multi-homing) and several link-locals. Each
	phase probes ALL addresses in parallel and exits on the first positive, so
	extra addresses cost packets, not wall time.

	`macs` is the device's full MAC set (it may rotate private Wi-Fi MACs);
	every identity check (arping reply source, neigh-table owner) accepts any
	of them.

	Returns ( verdict , info_dict ) with verdict ∈ {'reachable','absent','unknown'}.

	THOROUGH by design: every scan runs EVERY live probe against EVERY target —
	no early exit. All run concurrently, so wall time is the slowest single
	probe, not the sum. The verdict is based ONLY on live, on-the-wire probes:

	  - arping  : raw L2 ARP broadcast; reads the reply's source MAC live and
	              requires it to be one of the device's MACs. Does NOT consult
	              the kernel ARP cache. This is the ground-truth signal.
	  - tcp     : SYN to iOS Lockdown port 62078; a completed handshake proves
	              a live host at that IP this instant.
	  - ping    : ICMP echo.
	  - ping6   : ICMPv6 to link-local(s); independent OS stack on iOS.

	The kernel `ip neigh` table is a CACHE — it is read for information and
	current-IP discovery only, and never declares presence on its own. (ARP/
	neigh caches go stale and lie; that's why they don't get a vote here.)

	Verdict:
	  - any live probe answered                  -> reachable
	  - live probes ran and none answered         -> absent
	  - no probe could run (binaries missing)     -> unknown (defer to eero)
	"""
	if isinstance( ips , str ):
		ips = [ ips ]
	ips = [ ip for ip in dict.fromkeys( ips or [] ) if ip ]
	if isinstance( ipv6_link_locals , str ):
		ipv6_link_locals = [ ipv6_link_locals ]
	v6s = [ a for a in dict.fromkeys( ipv6_link_locals or [] ) if a ]

	macset = as_mac_set( macs )

	if not ENABLE_LOCAL_PROBES or not ips:
		return ( "unknown" , { "reason": "no_ip_or_probes_disabled" } )

	info = { "probed_ips": ips , "probed_v6": v6s }

	# Build every probe as a task: a UDP wake-nudge + arping + TCP + ping for each
	# IPv4, ping6 for each link-local. All run in one parallel batch — no early
	# exit. The nudge fires its datagrams in the first ~0.6s, while arping keeps
	# probing for ~10s, so the chip is woken before arping's later packets land.
	tasks = []
	for ip in ips:
		tasks.append( ( ( "nudge" , ip ) ,  lambda ip=ip: udp_nudge( ip ) ) )
		tasks.append( ( ( "arping" , ip ) , lambda ip=ip: arping_once( ip , expect_macs=macset ) ) )
		tasks.append( ( ( "tcp" , ip ) ,    lambda ip=ip: tcp_probe( ip ) and ip_owner_matches( ip , macset ) ) )
		tasks.append( ( ( "ping" , ip ) ,   lambda ip=ip: ping_once( ip ) and ip_owner_matches( ip , macset ) ) )
	if iface:
		for a in v6s:
			tasks.append( ( ( "ipv6" , a ) , lambda a=a: ping6_once( a , iface ) ) )

	res = _fanout_all( tasks )

	def _agg_method( method ):
		return _agg_probe( { k: v for k , v in res.items() if k[ 0 ] == method } )

	arp_reply = _agg_method( "arping" )
	tcp_ok    = _agg_method( "tcp" )
	ping_ok   = _agg_method( "ping" )
	ipv6_ok   = _agg_method( "ipv6" ) if v6s else None
	info[ "arping" ]   = arp_reply
	info[ "tcp_62078" ] = tcp_ok
	info[ "ping" ]     = ping_ok
	info[ "ipv6" ]     = ipv6_ok
	# per-target detail (which exact IP/addr answered which probe) for the log
	info[ "probe_detail" ] = { f"{m}@{t}": v for ( m , t ) , v in sorted( res.items() ) }

	# neigh table: current-IP discovery AND a presence signal. After the battery
	# above (which fired arping + a UDP nudge + a TCP SYN, all of which trigger
	# the kernel's ARP resolution), a state of REACHABLE means the device's chip
	# answered ARP within the kernel's reachable window (~30s) — i.e. it is
	# present right now, even if it ignored ICMP/TCP at L4 (asleep). This is the
	# "chip answers ARP without waking the CPU" case. STALE/FAILED do NOT count
	# (stale = unconfirmed old cache; failed = probed, no answer).
	neigh_confirmed = False
	if IS_LINUX:
		entries = neigh_entries_for( macset )
		states = [ s for _ , s in entries ]
		info[ "neigh_state" ] = best_neigh_state( states )
		info[ "neigh_ip" ] = entries[ 0 ][ 0 ] if entries else None
		neigh_confirmed = ( info[ "neigh_state" ] == "reachable" )
		info[ "neigh_confirmed" ] = neigh_confirmed
		v4s = [ ip for ip , _ in entries if _IPV4_RE.match( ip ) ]
		if v4s:
			# kernel's idea of the device's CURRENT IPv4 — callers adopt it as a
			# probe target when DHCP moved the device
			info[ "neigh_ipv4" ] = v4s[ 0 ]

	# Verdict: any live probe answered, OR the kernel just confirmed the device
	# at L2 (fresh REACHABLE) -> reachable.
	if True in ( arp_reply , tcp_ok , ping_ok , ipv6_ok ) or neigh_confirmed:
		return ( "reachable" , info )
	# At least one live probe actually ran (returned True/False, not None) and
	# none answered -> absent. If nothing could run (all None) -> defer to eero.
	if any( v is False for v in ( arp_reply , tcp_ok , ping_ok , ipv6_ok ) ):
		return ( "absent" , info )
	return ( "unknown" , info )

# Most-alive-first ordering for picking a representative state when a MAC has
# several neigh entries (a device usually has one v4 AND one or more v6).
_NEIGH_STATE_RANK = [ "reachable" , "delay" , "probe" , "permanent" , "stale" , "failed" ]

def best_neigh_state( states ):
	for s in _NEIGH_STATE_RANK:
		if s in states:
			return s
	return None

def read_linux_neigh_table():
	"""
	Linux `ip neigh show` — like ARP but exposes per-entry STATE.
	Returns { normalized_mac: [ ( ip , state_lower ) , ... ] } — a device
	usually has BOTH an IPv4 and one or more IPv6 entries, so values are
	lists (older versions kept one entry per MAC, letting v6 lines silently
	shadow the v4 one).

	State semantics (RFC 4861 / Linux kernel):
	  REACHABLE  : confirmed alive in last ~30s
	  DELAY      : queued for verification
	  PROBE      : ARP probes being sent right now
	  STALE      : entry exists but UNVERIFIED — could be a ghost
	  FAILED     : probed, no reply, device is gone
	  PERMANENT  : manually configured

	Treat states in FRESH_NEIGH_STATES as "device confirmed alive."
	"""
	if not ENABLE_LOCAL_PROBES or not IS_LINUX:
		return {}
	try:
		out = subprocess.run(
			[ "ip" , "neigh" , "show" ] , capture_output=True , text=True , timeout=5 ,
		).stdout
	except Exception as e:
		print( f"!! ip neigh failed: {e}" )
		return {}
	result = {}
	for line in out.splitlines():
		parts = line.split()
		if "lladdr" not in parts:
			continue
		try:
			idx = parts.index( "lladdr" )
			mac = normalize_mac( parts[ idx + 1 ] )
			ip = parts[ 0 ]
			state = parts[ -1 ].lower()
			result.setdefault( mac , [] ).append( ( ip , state ) )
		except ( ValueError , IndexError ):
			continue
	return result

def neigh_entries_for( macs , table=None ):
	"""All ( ip , state ) neigh entries belonging to ANY of the device's MACs."""
	want = as_mac_set( macs )
	if not want:
		return []
	table = read_linux_neigh_table() if table is None else table
	out = []
	for mac_n , entries in table.items():
		if mac_n in want:
			out.extend( entries )
	return out

def ip_owner_matches( ip , macs ):
	"""
	After a positive L3/L4 probe (TCP, ping) of `ip`, confirm via the kernel
	neigh table that the host which answered actually has one of OUR device's
	MACs. The probe itself forced ARP resolution, so an on-link responder is in
	the table. Returns False only on a confirmed mismatch (the IP was
	reassigned to a different device) — unknown/off-link cases pass through as
	True. Linux only; elsewhere it's a no-op.
	"""
	want = as_mac_set( macs )
	if not IS_LINUX or not want:
		return True
	try:
		out = subprocess.run(
			[ "ip" , "neigh" , "show" , ip ] , capture_output=True , text=True , timeout=5 ,
		).stdout
	except Exception:
		return True
	m = re.search( r"lladdr\s+(\S+)" , out )
	if not m:
		return True
	return normalize_mac( m.group( 1 ) ) in want


# ---------------------------------------------------------------------------
# Small file helpers
# ---------------------------------------------------------------------------

def append_jsonl( path , record ):
	with open( path , "a" ) as f:
		f.write( json.dumps( record , default=str ) + "\n" )

