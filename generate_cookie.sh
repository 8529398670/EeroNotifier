#!/usr/bin/env bash
# Regenerate the eero API session cookie (config.yaml -> paths.cookie,
# normally ./session.cookie) used by watch.py.
#
# eero has no passwords: you give the email or phone number on the eero
# account, eero sends a one-time code there, and verifying it yields the
# session token. The new token is written to a temp file and only replaces
# the live cookie after a test account() call succeeds — a failed or
# abandoned login never breaks the running cron job.
#
#   ./generate_cookie.sh                  # prompts for email/phone
#   ./generate_cookie.sh you@example.com  # or pass it
#   ./generate_cookie.sh --check          # just test the current cookie

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR" || exit 1

# Python goes in via -c (not a stdin heredoc) so input() can read the terminal.
PYCODE=$( cat <<'EOF'
import os, sys, tempfile

import eero as eero_pkg
from config import get as _cfg
from utils import CookieStore

COOKIE_PATH = os.path.abspath( _cfg( "paths.cookie" , "session.cookie" ) )

def networks_of( client ):
	nets = client.account().get( "networks" , {} ).get( "data" , [] )
	return [ n.get( "name" ) for n in nets ]

args = sys.argv[ 1: ]

if args[ :1 ] == [ "--check" ]:
	client = eero_pkg.Eero( CookieStore( COOKIE_PATH ) )
	if client.needs_login():
		sys.exit( f"!! no cookie at {COOKIE_PATH} — run without --check to log in." )
	try:
		print( f"cookie OK — networks: {networks_of( client )}" )
	except Exception as e:
		sys.exit( f"!! cookie at {COOKIE_PATH} rejected: {e}" )
	sys.exit( 0 )

identifier = args[ 0 ] if args else input( "eero account email or phone (+15551234567): " ).strip()
if not identifier:
	sys.exit( "!! no email/phone given." )

fd , tmp_path = tempfile.mkstemp( prefix=".session.cookie." , dir=os.path.dirname( COOKIE_PATH ) )
os.close( fd )
os.unlink( tmp_path )   # CookieStore treats a missing file as "no cookie yet"
try:
	client = eero_pkg.Eero( CookieStore( tmp_path ) )
	user_token = client.login( identifier )
	code = input( f"verification code eero sent to {identifier}: " ).strip()
	client.login_verify( code , user_token )
	names = networks_of( client )   # proves the new token works before we swap it in
	os.chmod( tmp_path , 0o600 )
	os.replace( tmp_path , COOKIE_PATH )
	print( f"saved {COOKIE_PATH} — networks on this account: {names}" )
	want = _cfg( "network" , None )
	if want is not None and want not in names:
		print( f"!! warning: config.yaml network {want!r} is not on this account." )
except Exception as e:
	sys.exit( f"!! login failed ({e}) — existing cookie left untouched." )
finally:
	if os.path.exists( tmp_path ):
		os.unlink( tmp_path )
EOF
)
exec "$DIR/venv/bin/python" -c "$PYCODE" "$@"
