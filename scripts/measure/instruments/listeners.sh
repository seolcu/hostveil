#!/usr/bin/env bash
# What the kernel says is listening, and on which address.
#
# The external scan asks what answers from off the host; this asks what is
# bound, which is the question the compose port-binding fixes are actually
# about. The two disagree in an informative way: a port bound to 0.0.0.0
# whose backend is not serving refuses a connection, so an external scan
# reads it as closed while the binding is still wide open — and the moment
# something starts serving behind it, it is exposed.
#
# The kernel's own answer, and so independent of hostveil in the only sense
# that matters: nothing here consults a rule set, ours or anyone's.
set -euo pipefail

command -v ss >/dev/null || { echo '{"error":"ss (iproute2) not installed"}'; exit 0; }

ss -ltnH 2>/dev/null | python3 -c '
import json, sys
public, loopback = [], []
for line in sys.stdin:
    cols = line.split()
    if len(cols) < 4:
        continue
    addr, _, port = cols[3].rpartition(":")
    addr = addr.strip("[]")
    try:
        port = int(port)
    except ValueError:
        continue
    # A wildcard bind is reachable on every interface the host has; "*" is
    # how ss writes the v6 wildcard.
    if addr in ("0.0.0.0", "::", "*", ""):
        public.append(port)
    elif addr.startswith("127.") or addr == "::1":
        loopback.append(port)
    else:
        public.append(port)
print(json.dumps({
    "wildcard_or_routable_tcp": sorted(set(public)),
    "loopback_only_tcp": sorted(set(loopback)),
    "count": len(set(public)),
}))'
