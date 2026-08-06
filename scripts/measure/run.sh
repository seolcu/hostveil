#!/usr/bin/env bash
# Measure what hostveil actually changes, using instruments that are not
# hostveil.
#
# The end-to-end test already proves the score goes up after `fix --all`. That
# is hostveil marking its own homework: the same code decides what a finding
# is, what fixing it means, and what the number should be afterwards. It can
# be wholly self-consistent and wholly wrong.
#
# So this runs auditors that have never heard of hostveil — Lynis, the CIS
# Docker Benchmark, a TCP connect scan from off the host, and the kernel's own
# list of listening sockets — and reports what each of them saw. Including
# where they did not move, because a fix that improves hostveil's own score
# and nothing else is exactly what this exists to catch.
#
# Four phases: before the fixes, after them, after the services have been
# restarted into them, and after every one has been rolled back.
#
# It measures the host it runs on, the way hostveil does. Point it at a host
# you are willing to have edited: it applies every Auto fix and then rolls
# them all back.
#
#   scripts/measure/run.sh [-p profile] [output.json]
#
# Requires root. Lynis and docker-bench-security are optional — a missing one
# is recorded as absent rather than passed over silently.
#
# The order below is the whole design. Rollback fidelity is judged against
# hashes taken *before* the fixes ran, on paths hostveil's own scan named, so
# "restored" means the filesystem came back — not that hostveil agrees with
# its own checkpoints.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PROFILE=seeded
while getopts ":p:" opt; do
  case "$opt" in
    p) PROFILE=$OPTARG ;;
    *) echo "usage: $0 [-p profile] [output.json]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
OUT=${1:-/dev/stdout}

export MEASURE_MARK=${MEASURE_MARK:-/tmp/hostveil-measure-mark}

[ "$(id -u)" = 0 ] || { echo "measure: needs root — it reads /etc/shadow and edits system files" >&2; exit 1; }
command -v hostveil >/dev/null || { echo "measure: hostveil is not on PATH" >&2; exit 1; }

# hostveil is already root here, so the re-exec would only add a prompt.
export HOSTVEIL_NO_SUDO=1

WORK=$(mktemp -d /tmp/hostveil-measure-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

say() { printf '==> %s\n' "$*" >&2; }
rb() { "$HERE/instruments/rollback.sh" "$@"; }

instrument() {
  local name=$1
  if [ -x "$HERE/instruments/$name.sh" ]; then
    "$HERE/instruments/$name.sh" 2>/dev/null || echo '{"error":"instrument failed"}'
  else
    echo '{"error":"instrument missing"}'
  fi
}

# Each phase runs every instrument and lands one file apiece. A failing
# instrument records its failure in place rather than dropping the phase: a
# missing number and a number that did not move are different results, and
# the report must never let one read as the other.
measure_all() {
  local phase=$1
  for i in hostveil lynis dockerbench extscan listeners; do
    say "$phase: $i"
    instrument "$i" > "$WORK/$phase.$i.json"
  done
}

# Every Auto fix is a file edit, which is what makes it reversible — and
# means none of it is in force until whatever reads that file reads it again.
# A running container keeps the port mapping it was created with, and sshd
# keeps serving from the config it already loaded.
#
# So the harness measures twice: once with the files changed and the host
# untouched, and once after the services have been restarted into them.
# Without the second, an instrument reading the running system reports that
# nothing happened, which is true and reads as though the fixes did nothing.
# Without the first, the report would quietly credit hostveil with a restart
# it does not perform and deliberately does not offer as an Auto fix.
restart_services() {
  for f in $(hostveil scan --json 2>/dev/null |
    python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except ValueError:
    raise SystemExit
seen = set()
for f in r["findings"]:
    for src in (f.get("metadata") or {}, f.get("evidence") or {}):
        for v in src.values():
            v = str(v)
            if v.endswith((".yml", ".yaml")) and v.startswith("/") and v not in seen:
                seen.add(v)
                print(v)' || true); do
    say "  docker compose -f $f up -d"
    docker compose -f "$f" up -d >/dev/null 2>&1 || true
  done
  # sshd reloads its configuration without dropping established sessions,
  # which is the only reason this is safe to do to a host you are on.
  systemctl reload ssh >/dev/null 2>&1 ||
    systemctl reload sshd >/dev/null 2>&1 ||
    say "  no systemd ssh unit to reload"
}

say "profile $PROFILE — recording where the fix history stands"
rb mark > "$WORK/checkpoints.before"
rb dirs > "$WORK/dirs"

say "hashing the before-state of every path a finding points at"
rb candidates > "$WORK/paths.before"
rb hash < "$WORK/paths.before" > "$WORK/hash.before"
say "$(wc -l < "$WORK/paths.before" | tr -d ' ') paths watched"

say "BEFORE"
measure_all before

say "applying every Auto fix"
hostveil fix --all --yes > "$WORK/fix.log" 2>&1 || true
tail -3 "$WORK/fix.log" >&2 || true

say "AFTER (files changed, nothing restarted)"
measure_all after

say "restarting the services into their new configuration"
restart_services

say "RESTARTED"
measure_all restarted

# The union, because a fix may create a file that was not there to be listed
# before, and may clear a finding whose file therefore stops being named.
say "hashing what the fixes left"
rb candidates > "$WORK/paths.after"
sort -u "$WORK/paths.before" "$WORK/paths.after" > "$WORK/paths.union"
rb hash < "$WORK/paths.union" > "$WORK/hash.after"

say "rolling every checkpoint back"
rb undo > "$WORK/undone"
rb hash < "$WORK/paths.union" > "$WORK/hash.restored"

# The rollback restored the files; the services are still running the fixed
# configuration until they are restarted out of it too. Without this the
# restored phase would measure a host that is half rolled back.
say "restarting the services back out of it"
restart_services

say "RESTORED"
measure_all restored

"$HERE/report.py" "$WORK" "$PROFILE" > "$OUT"
say "wrote $OUT"
