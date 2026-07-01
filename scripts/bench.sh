#!/usr/bin/env bash
# Run all Go benchmarks and produce a report.
#
# Usage:
#   scripts/bench.sh                 # run every benchmark once
#   scripts/bench.sh -benchtime=3s   # pass through to `go test -bench`
#   scripts/bench.sh -bench=Snapshot # filter benchmarks
#   scripts/bench.sh -count=N        # run each benchmark N times
#
# Output is written to stdout. Capture with `scripts/bench.sh | tee bench.txt`
# to keep a record for `benchstat` comparison.
#
# Why a script and not a Makefile: the project intentionally has no
# Makefile (see AGENTS.md and DEVELOPMENT.md). This script is the
# one entry point for "run the benchmarks".

set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
    echo "go not found in PATH" >&2
    exit 1
fi

# Forward everything after the first arg to `go test -bench`. Default
# to running every benchmark in every internal package once with the
# race detector off (race inflates ns/op substantially and benchmarks
# are not concurrency tests).
extra_args=("$@")
if [[ ${#extra_args[@]} -eq 0 ]]; then
    extra_args=("-bench=." "-benchtime=1x")
fi

# Run from the repo root so the package paths are stable regardless
# of where the user invokes the script.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "=== hostveil benchmarks ==="
echo "go:    $(go version | awk '{print $3}')"
echo "date:  $(date -Iseconds)"
echo "host:  $(uname -srm)"
echo "args:  ${extra_args[*]}"
echo

# -run=^$ excludes the regular test suite. `-bench=.` runs every
# benchmark in the package. `-benchmem` keeps allocation reporting
# on. `-count=1` is the default; pass `-count=N` to repeat.
go test -run='^$' -benchmem "${extra_args[@]}" ./internal/...
