#!/usr/bin/env bash
# Lynis: an independent host auditor with its own rule set, its own opinions,
# and no knowledge of hostveil. Its hardening index is the headline.
#
# --quick skips the tests that wait for input; --quiet drops the running
# commentary. The report file is the machine-readable output; the terminal
# output is not meant to be parsed.
#
# The index alone is too coarse to be evidence. It is one number over 245
# tests, so a change to three SSH options can be real and still round to the
# same integer — and "the index did not move" would then read as "nothing
# happened", which is a different claim. So the test IDs behind every warning
# and suggestion come out too: those are a set, and a set can be diffed. What
# hostveil cleared is exactly what leaves it.
set -euo pipefail

# An auditor that did not run must not be reported as an auditor that found
# nothing. Without this the block below emits hardening_index null with zero
# warnings and zero suggestions, which is the JSON a perfectly hardened host
# would produce — and the demo VM has no lynis, because the tools come from
# scripts/measure/seed.sh and that is not what provisions it. dockerbench.sh
# already refuses this way; this one was measuring its own absence as a pass.
command -v lynis >/dev/null || { echo '{"error":"lynis not installed"}'; exit 0; }

lynis audit system --quick --quiet --no-colors >/dev/null 2>&1 || true

python3 - <<'PY'
import json
report = "/var/log/lynis-report.dat"
idx, tests = None, 0
warnings, suggestions = set(), set()
try:
    for line in open(report, errors="replace"):
        key, _, value = line.rstrip("\n").partition("=")
        if key == "hardening_index":
            idx = int(value)
        elif key == "warning[]":
            warnings.add(value.split("|")[0])
        elif key == "suggestion[]":
            suggestions.add(value.split("|")[0])
        elif key == "tests_executed":
            tests = len([t for t in value.split("|") if t])
except FileNotFoundError:
    print(json.dumps({"error": "lynis left no report at " + report}))
    raise SystemExit(0)
print(json.dumps({
    "hardening_index": idx,
    "tests_executed": tests,
    "warnings": len(warnings),
    "suggestions": len(suggestions),
    "warning_ids": sorted(warnings),
    "suggestion_ids": sorted(suggestions),
}))
PY
