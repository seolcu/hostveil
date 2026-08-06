#!/usr/bin/env bash
# hostveil's own score, per axis, and its coverage. The self-measurement —
# reported alongside the independent ones precisely so a reader can see
# whether they move together.
set -euo pipefail

# `scan` exits 1 when it finds anything exposed — the documented CI contract,
# and the ordinary case here. Capture first so the status is the parser's.
scan=$(hostveil scan --json 2>/dev/null || true)

printf '%s' "$scan" | python3 -c '
import json, sys
r = json.load(sys.stdin)
axes = {a["id"]: (a["score"] if a["applicable"] else None) for a in r["score"]["axes"]}
sev = {}
for f in r["findings"]:
    sev[f["severity"]] = sev.get(f["severity"], 0) + 1
print(json.dumps({
    "overall": r["score"]["overall"] if r["score"]["applicable"] else None,
    "applicable": r["score"]["applicable"],
    "findings": len(r["findings"]),
    "by_severity": sev,
    "axes": axes,
    "domains_run": sum(1 for d in r["domains"] if d["state"] in ("done", "degraded")),
    "domains_complete": sum(1 for d in r["domains"] if d["state"] == "done"),
}))'
