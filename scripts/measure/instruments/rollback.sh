#!/usr/bin/env bash
# Rollback fidelity: does undoing every fix put the host back byte for byte?
#
# Not a security measurement — a claim about the recovery layer, and the one
# that has to hold for any of the rest to be worth running. hostveil asks an
# operator to let it edit files on a server, and "you can undo it" is the
# reason that is acceptable.
#
# The hashing is deliberately not done from the checkpoints. A checkpoint
# records what hostveil believes it backed up, so comparing a restored file
# against it asks whether hostveil agrees with itself. The candidate paths
# come from the scan instead — every file a finding points at — and they are
# hashed on the live filesystem before anything is applied. That is the state
# a rollback has to reproduce.
#
#   rollback.sh candidates  → the paths any finding points at
#   rollback.sh dirs        → directories enumerated whole by `candidates`
#   rollback.sh hash        → sha256 each path on stdin, absent marked ABSENT
#   rollback.sh mark        → record which checkpoints existed before
#   rollback.sh new         → the checkpoints created since the mark
#   rollback.sh undo        → roll those back, newest first
set -euo pipefail

MARK=${MEASURE_MARK:-/tmp/hostveil-measure-mark}

# Directories listed entry by entry rather than only where a finding names a
# file inside them. A fix that *creates* a file is invisible in the
# before-state — nothing points at a path that does not exist yet — so its
# absence has to be recorded some other way, and enumerating the directory is
# that way. sysctl is the case that needs it: persistSysctl writes a new
# 60-hostveil-*.conf, and without this a run could not tell "rollback removed
# the file it created" from "the file was never watched".
ENUMERATED_DIRS=${MEASURE_ENUMERATED_DIRS:-/etc/sysctl.d}

ids() { hostveil history 2>/dev/null | grep -oE 'rollback [0-9]{8}-[0-9.]+-[0-9a-f]+-[0-9a-f]+' | awk '{print $2}'; }

case "${1:-}" in
candidates)
  # Every absolute path a finding carries, from metadata and evidence alike,
  # plus every entry of the enumerated directories. A superset on purpose:
  # hashing a file no fix touches costs nothing, and missing one would
  # silently narrow what "restored" is claiming.
  # `scan` exits 1 whenever it finds anything exposed, which is the whole
  # point of running it here. Capture before piping so pipefail does not read
  # a successful scan as a failed instrument.
  scan=$(hostveil scan --json 2>/dev/null || true)
  printf '%s' "$scan" | ENUMERATED_DIRS="$ENUMERATED_DIRS" python3 -c '
import json, os, sys
paths = set()
for f in json.load(sys.stdin)["findings"]:
    for src in (f.get("metadata") or {}, f.get("evidence") or {}):
        for v in src.values():
            for part in str(v).split(","):
                part = part.strip()
                if part.startswith("/") and os.path.isfile(part):
                    paths.add(part)
for d in os.environ["ENUMERATED_DIRS"].split(":"):
    if os.path.isdir(d):
        for n in os.listdir(d):
            p = os.path.join(d, n)
            if os.path.isfile(p):
                paths.add(p)
for p in sorted(paths):
    print(p)'
  ;;
dirs) printf '%s\n' "$ENUMERATED_DIRS" | tr ':' '\n' ;;
hash)
  sort -u | while read -r f; do
    [ -n "$f" ] || continue
    if [ -f "$f" ]; then printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"
    else printf '%s  %s\n' ABSENT "$f"; fi
  done
  ;;
mark)  ids > "$MARK"; wc -l < "$MARK" | tr -d ' ' ;;
new)   comm -23 <(ids | sort) <(sort "$MARK" 2>/dev/null || true) ;;
undo)
  n=0
  # Newest first: two fixes to one file leave the second's content in place,
  # and a rollback verifies against what it wrote.
  for id in $("$0" new | sort -r); do
    if hostveil rollback "$id" >/dev/null 2>&1; then n=$((n+1)); fi
  done
  echo "$n"
  ;;
*) echo "usage: $0 {candidates|dirs|hash|mark|new|undo}" >&2; exit 2 ;;
esac
