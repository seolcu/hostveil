#!/usr/bin/env bash
# What is reachable from off the host.
#
# This is the instrument that answers the question a score cannot: after the
# fixes, is the datastore still answering the network? It runs from inside a
# container on the default bridge, connecting back to the host's bridge
# address — so it reaches exactly what a service bound to 0.0.0.0 exposes and
# nothing bound to loopback, which is the distinction the whole exercise is
# about.
#
# A container rather than a second machine because it needs no fixture and
# no credentials, and because the bridge address is off-host by every
# definition that matters here: a different network namespace, arriving on an
# interface, subject to the host firewall.
#
# Three outcomes, not two. A port that answers, a port that refuses, and a
# port whose packets vanish are three different states, and collapsing the
# last two into "closed" would erase the difference between "the service
# stopped listening" and "the firewall now drops it" — which is precisely the
# distinction between two of the fixes being measured.
set -euo pipefail

IMAGE=${EXTSCAN_IMAGE:-alpine:3.14}
# The ports hostveil itself has opinions about: SSH, the Docker API, the
# datastores that ship with no password, the dashboards, and the two agent
# gateways (11434 Ollama, 18789 OpenClaw).
PORTS=${EXTSCAN_PORTS:-"22 80 443 2375 2376 3306 5432 6379 6380 8080 8086 8096 9000 9090 11211 11434 18789 27017"}

gw=$(ip -4 addr show docker0 2>/dev/null | grep -oP '(?<=inet )[\d.]+' | head -1)
[ -n "$gw" ] || { echo '{"error":"no docker0 bridge to scan from"}'; exit 0; }

# busybox nc's -w is a *connect* timeout and nothing else — it does not bound
# the wait for data. So a port that accepts and then says nothing hangs
# forever, which is every one of the datastores this is pointed at. The outer
# `timeout` is what bounds that, and the pair of them is also what separates
# the three outcomes:
#
#   rc 0 or 143   the connect succeeded  → open
#                 (0 = the peer closed, 143 = it was still open when we gave up)
#   rc≠0, fast    ECONNREFUSED           → refused, nothing is listening
#   rc≠0, ~2s     nc's own -w expired    → filtered, the packets went nowhere
#
# One second of clock granularity is enough to tell the last two apart: a
# refusal comes back in well under a second and a drop costs the full -w.
raw=$(docker run --rm --network bridge "$IMAGE" sh -c "
  for p in $PORTS; do
    s=\$(date +%s)
    timeout 3 nc -w 2 $gw \$p >/dev/null 2>&1
    rc=\$?
    d=\$(( \$(date +%s) - s ))
    if [ \$rc = 0 ] || [ \$rc -ge 124 ]; then echo \"open \$p\"
    elif [ \$d -ge 2 ]; then echo \"filtered \$p\"
    else echo \"refused \$p\"; fi
  done" 2>/dev/null)

printf '%s\n' "$raw" | python3 -c '
import json, sys
state = {"open": [], "refused": [], "filtered": []}
for line in sys.stdin:
    parts = line.split()
    if len(parts) == 2 and parts[0] in state:
        state[parts[0]].append(int(parts[1]))
print(json.dumps({
    "from": "container on the docker bridge",
    "target": sys.argv[1],
    "reachable_tcp": sorted(state["open"]),
    "refused_tcp": sorted(state["refused"]),
    "filtered_tcp": sorted(state["filtered"]),
    "count": len(state["open"]),
}))' "$gw"
