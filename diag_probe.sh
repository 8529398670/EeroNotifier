#!/usr/bin/env bash
# TEMPORARY diagnostic — added during 2026-06-12 debugging of a phantom
# lan_present for one watched iPhone. Safe to delete.
# Appends one snapshot per run. Target comes from config.yaml -> diag_probe
# (ip, mac_prefix) so no addresses live in this script.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PY="$DIR/venv/bin/python"
cfg() { ( cd "$DIR" && "$PY" -c "from config import get; print(get('$1', '') or '')" ); }
IP=$( cfg diag_probe.ip )
MAC_PREFIX=$( cfg diag_probe.mac_prefix )
[ -n "$IP" ] || { echo "diag_probe.ip not set in config.yaml" >&2; exit 1; }
export IP
OUT="$DIR/diag_probe.out"

{
	echo "===== $(date '+%F %T %z') ====="
	echo "--- ip -4 addr"
	ip -4 addr show | grep -w inet
	echo "--- route to $IP"
	ip route get "$IP" 2>&1
	echo "--- neigh (before)"
	ip neigh show | grep -iE "${IP}${MAC_PREFIX:+|$MAC_PREFIX}" || echo "(no entry)"

	echo "--- arping"
	if command -v arping >/dev/null 2>&1; then
		IFACE=$( ip route get "$IP" | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1 )
		arping -I "$IFACE" -c 5 -w 5 -f "$IP" 2>&1
		echo "arping exit: $?"
	else
		echo "arping NOT installed"
	fi

	echo "--- tcp connect_ex to ${IP}:62078"
	"$PY" - <<'EOF'
import os, socket, errno
s = socket.socket()
s.settimeout(2)
r = s.connect_ex((os.environ["IP"], 62078))
name = "OK(connected)" if r == 0 else errno.errorcode.get(r, str(r))
print("connect_ex ->", r, name)
try:
	print("peer:", s.getpeername(), "local:", s.getsockname())
except OSError as e:
	print("getpeername:", e)
s.close()
EOF

	echo "--- icmp ping"
	ping -c 3 -W 1 "$IP" 2>&1 | tail -3

	echo "--- lockdownd identify"
	timeout 10 "$PY" - <<'EOF'
import os, socket, plistlib, struct
try:
	s = socket.create_connection((os.environ["IP"], 62078), timeout=3)
	s.settimeout(3)
	def send(d):
		p = plistlib.dumps(d, fmt=plistlib.FMT_XML)
		s.sendall(struct.pack(">I", len(p)) + p)
	def recv():
		hdr = b""
		while len(hdr) < 4:
			c = s.recv(4 - len(hdr))
			if not c: raise EOFError("closed during header")
			hdr += c
		n = struct.unpack(">I", hdr)[0]
		buf = b""
		while len(buf) < n:
			c = s.recv(n - len(buf))
			if not c: raise EOFError("closed during body")
			buf += c
		return plistlib.loads(buf)
	send({"Request": "QueryType"})
	print("QueryType:", recv())
	send({"Request": "GetValue"})
	print("GetValue(all):", recv())
	send({"Request": "GetValue", "Key": "DeviceName"})
	print("GetValue(DeviceName):", recv())
	s.close()
except Exception as e:
	print("lockdown query failed:", type(e).__name__, e)
EOF

	echo "--- neigh (after)"
	ip neigh show | grep -iE "${IP}${MAC_PREFIX:+|$MAC_PREFIX}" || echo "(no entry)"
	echo "--- neigh (full table)"
	ip neigh show
	echo
} >> "$OUT" 2>&1
