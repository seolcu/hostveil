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
# Five phases: before the fixes, after them, after the services have been
# restarted into them, after every reversible Review fix has been accepted as
# well, and after every one has been rolled back.
#
# It measures the host it runs on, the way hostveil does. Point it at a host
# you are willing to have edited: it applies every Auto fix and then rolls
# them all back.
#
#   scripts/measure/run.sh [-c] [-p profile] [output.json]
#
# -C measures the control group instead: the same instruments, before and
# after control.sh hardens the host from the CIS Benchmarks *without*
# hostveil. It answers the question the run above cannot — does the score go
# up when the host is hardened by somebody else's standard? A number that only
# responds to hostveil's own fixes is not a security score, it is a to-do list
# with a percentage on it. No fix, no rollback, and the profile defaults to
# "control".
#
# Requires root. Lynis and docker-bench-security are optional — a missing one
# is recorded as absent rather than passed over silently.
#
# -c exits non-zero when either of hostveil's two promises breaks. Nothing
# else here is asserted, because everything else is an observation: an
# instrument moves for reasons that have nothing to do with a diff — a Lynis
# release, a new distribution default — and a check that turns red for those
# is a check somebody turns off.
#
# The order below is the whole design. Rollback fidelity is judged against
# hashes taken *before* the fixes ran, on paths hostveil's own scan named, so
# "restored" means the filesystem came back — not that hostveil agrees with
# its own checkpoints.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PROFILE=
CHECK=0
CONTROL=0
while getopts ":cCp:" opt; do
  case "$opt" in
    c) CHECK=1 ;;
    C) CONTROL=1 ;;
    p) PROFILE=$OPTARG ;;
    *) echo "usage: $0 [-c] [-C] [-p profile] [output.json]" >&2; exit 2 ;;
  esac
done
# The default names the experiment rather than the host, because that is what
# distinguishes the two runs in docs/measurements/ and what the docs tests
# select on: the published pages describe the seeded run, and a control run
# that landed under the same profile would be read as the newest of them.
if [ -z "$PROFILE" ]; then
  if [ "$CONTROL" = 1 ]; then PROFILE=control; else PROFILE=seeded; fi
fi
shift $((OPTIND - 1))
OUT=${1:-/dev/stdout}

[ "$(id -u)" = 0 ] || { echo "measure: needs root — it reads /etc/shadow and edits system files" >&2; exit 1; }
command -v hostveil >/dev/null || { echo "measure: hostveil is not on PATH" >&2; exit 1; }

# hostveil is already root here, so the re-exec would only add a prompt.
export HOSTVEIL_NO_SUDO=1

WORK=$(mktemp -d /tmp/hostveil-measure-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
export MEASURE_MARK=${MEASURE_MARK:-"$WORK/checkpoints.mark"}

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
  # AUTO sysctl fixes intentionally persist reversible drop-ins without
  # mutating the running kernel. This phase is the explicit activation step
  # that the report labels as restarted/applied, analogous to reloading sshd.
  sysctl --system >/dev/null 2>&1 || say "  sysctl --system could not apply every persisted value"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    say "  docker compose -f $f up -d"
    docker compose -f "$f" up -d >/dev/null 2>&1 || true
  done < <(hostveil scan --json 2>/dev/null |
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
                print(v)' || true)
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

# The control group. Everything below this branch is about hostveil applying
# fixes and undoing them, and a control run does none of it: the point is to
# harden the host by somebody else's standard and ask whether hostveil's score
# notices. There is nothing to roll back because hostveil changed nothing, and
# control.sh does not undo itself — which is why it says to run it on
# something disposable.
if [ "$CONTROL" = 1 ]; then
  say "hardening the host from the CIS Benchmarks, without hostveil"
  "$HERE/control.sh" >&2

  # Same reload the fixed path gets, for the same reason: control.sh writes an
  # sshd drop-in, and sshd keeps serving from the config it already loaded.
  restart_services

  say "CONTROLLED"
  measure_all controlled

  "$HERE/report.py" "$WORK" "$PROFILE" > "$OUT"
  say "wrote $OUT"

  if [ "$CHECK" = 1 ]; then
    if [ "$OUT" = /dev/stdout ]; then
      echo "measure: -c needs an output file to read back" >&2
      exit 2
    fi
    "$HERE/check.py" "$OUT"
  fi
  exit 0
fi

say "applying every Auto fix"
hostveil fix --all --yes > "$WORK/fix.log" 2>&1 || true
tail -3 "$WORK/fix.log" >&2 || true

say "AFTER (files changed, nothing restarted)"
measure_all after

say "restarting the services into their new configuration"
restart_services

say "RESTARTED"
measure_all restarted

# Everything above measures `fix --all`, which applies Auto fixes only —
# the unattended path, and deliberately the most conservative thing hostveil
# does. It is not the path an operator takes. They read a Review fix, decide,
# and accept it, and the fixes that need that decision are the ones that
# change the most: every SSH hardening option, because a bad sshd_config can
# lock the operator out, and hostveil will not do that unattended.
#
# So there is a fifth phase for the reviewed path, and it runs the command a
# user would run — `fix --all --review` — rather than a loop of its own. A
# harness that drives the tool differently from the way it ships measures
# something nobody will experience.
#
# It then counts how many of those fixes left a checkpoint, because that — not
# a word in a preview — is what "reversible" means here: an exec fix writes
# none, so the rollback phase below cannot put it back, and the report has to
# say how many of those there were rather than let "restored" read as a full
# undo.
#
# Counted rather than avoided, and counted from the checkpoint log rather
# than from the preview text. The first version of this read the preview and
# grepped it for "These commands will run:", which is the *TUI's* wording;
# the CLI says "The following commands will run:", so it matched nothing and
# skipped nothing while reporting that it had. A harness that tells you what
# it skipped, wrongly, is worse than one that does not skip.
checkpoint_count() { hostveil history 2>/dev/null | grep -cE 'rollback [0-9]{8}-' || true; }

apply_reviewed() {
  local cp_before cp_after applied
  cp_before=$(checkpoint_count)
  hostveil fix --all --review --yes > "$WORK/fix.reviewed.log" 2>&1 || true
  cp_after=$(checkpoint_count)
  applied=$(grep -cE '^  • ' "$WORK/fix.reviewed.log" || true)
  local reversible=$((cp_after - cp_before))
  local irreversible=$((applied - reversible))
  [ "$irreversible" -ge 0 ] || irreversible=0
  printf '{"applied":%d,"left_a_checkpoint":%d,"not_reversible":%d}\n' \
    "$applied" "$reversible" "$irreversible" > "$WORK/reviewed.json"
  say "  $applied fixes offered, $reversible reversible, $irreversible with no checkpoint"
}

say "hostveil fix --all --review — everything the tool can do, the way an operator who read it would"
apply_reviewed
restart_services

say "REVIEWED"
measure_all reviewed

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

if [ "$CHECK" = 1 ]; then
  if [ "$OUT" = /dev/stdout ]; then
    echo "measure: -c needs an output file to read back" >&2
    exit 2
  fi
  "$HERE/check.py" "$OUT"
fi
