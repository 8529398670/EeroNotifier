"""
Single source of configuration for EeroNotifier.

All deployment-specific values (which eero network to watch, Pushover token)
AND all operational tuning (presence thresholds, probe timing, etc.) live in
`config.yaml` next to this file. watch.py and utils.py read everything from
here, so those two .py files stay BYTE-IDENTICAL across every box — only
config.yaml differs per deployment.

Usage:
    from config import get
    LEAVE_MINUTES = get("presence.leave_minutes", 4)
    TOKEN         = get("pushover.token")
"""
import sys
from pathlib import Path

import yaml

_CONFIG_PATH = Path( __file__ ).resolve().parent / "config.yaml"


def _load():
	try:
		with open( _CONFIG_PATH ) as f:
			cfg = yaml.safe_load( f )
	except FileNotFoundError:
		sys.exit( f"!! config.yaml not found at {_CONFIG_PATH} — refusing to run "
		          f"without per-deployment config (network + pushover token)." )
	except Exception as e:
		sys.exit( f"!! config.yaml unreadable ({e}) — aborting." )
	if not isinstance( cfg , dict ):
		sys.exit( f"!! config.yaml did not parse to a mapping — aborting." )
	return cfg


CONFIG = _load()

# Sentinel so `get(path)` with no default can distinguish "missing" from "None".
_MISSING = object()


def get( path , default=_MISSING ):
	"""Dotted lookup into config.yaml, e.g. get('pushover.token').

	With no default, a missing key is a hard error (a typo'd path or an
	incomplete config should fail loudly at startup, not silently disable a
	feature or send to the wrong Pushover account)."""
	cur = CONFIG
	for key in path.split( "." ):
		if not isinstance( cur , dict ) or key not in cur:
			if default is _MISSING:
				sys.exit( f"!! required config key '{path}' missing from config.yaml — aborting." )
			return default
		cur = cur[ key ]
	return cur
