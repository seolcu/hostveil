#!/usr/bin/env bash
# docker-bench-security: the CIS Docker Benchmark as a shell script, from
# Docker themselves. Independent of hostveil and considerably broader — it
# audits the daemon, the host, images and every running container.
#
# Only the sections about images and running containers are run. The host
# and daemon sections ask about things this measurement does not change
# (auditd rules, the daemon's own binary), and running them adds minutes.
set -euo pipefail

BENCH=${DOCKER_BENCH_DIR:-/opt/docker-bench-security}
[ -x "$BENCH/docker-bench-security.sh" ] || { echo '{"error":"docker-bench-security not installed"}'; exit 0; }

log=$(mktemp -u /tmp/dbench-XXXX)
(cd "$BENCH" && ./docker-bench-security.sh -l "$log" -c container_images,container_runtime >/dev/null 2>&1) || true

python3 - "$log.json" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(json.dumps({"error": str(e)})); raise SystemExit
# The check IDs behind the counts, because a count that does not move and a
# set that does not move are different claims and only the second is
# evidence. 4.1 clearing while 5.25 appears leaves both totals at 16.
counts, warned = {}, []
for section in d.get("tests", []):
    for r in section.get("results", []):
        result = r.get("result", "?")
        counts[result] = counts.get(result, 0) + 1
        if result == "WARN":
            warned.append(r.get("id"))
print(json.dumps({
    "version": d.get("dockerbenchsecurity"),
    "checks": d.get("checks"),
    "score": d.get("score"),
    "results": counts,
    "warn_ids": sorted(i for i in warned if i),
}))
PY
