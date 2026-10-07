#!/usr/bin/env bash
# Run the full local CI gate, one step at a time, and say which step failed.
#
# Usage:
#   scripts/gate.sh            # every step
#   scripts/gate.sh -fast      # skip the race detector and cross-compile
#
# Why this exists rather than the `a && b && c` line AGENTS.md used to give:
# a chain stops at the first failure and prints nothing about it. `gofmt -l .`
# exits 0 whether or not it lists files, so the chain needed `test -z
# "$(gofmt -l .)"`, and when that test failed every later step — including
# the race tests — silently did not run. The run looked clean, and the first
# thing to notice was CI. Every step here runs, and each one is reported by
# name with the tail of its output when it fails.
#
# golangci-lint is the released binary, fetched once into the cache: `go run
# …@v2.12.2` refuses to run on this module's toolchain before it reads the
# config, which is a lint that lints nothing (see AGENTS.md).

set -uo pipefail

LINT_VERSION=2.12.2
GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck@v1.6.0

cd "$(dirname "$0")/.." || exit 1

fast=false
if [[ ${1:-} == "-fast" ]]; then
    fast=true
fi

failed=()

step() {
    local name=$1
    shift
    local out
    if out=$("$@" 2>&1); then
        printf 'ok   %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name"
        printf '%s\n' "$out" | tail -20 | sed 's/^/     /'
        failed+=("$name")
    fi
}

gofmt_clean() {
    local unformatted
    unformatted=$(gofmt -l .)
    [[ -z $unformatted ]] || { printf '%s\n' "$unformatted"; return 1; }
}

tidy_clean() {
    go mod tidy && git diff --exit-code go.mod go.sum
}

cross_compile() {
    local os arch
    for os in linux darwin; do
        for arch in amd64 arm64; do
            GOOS=$os GOARCH=$arch go build -o /dev/null ./cmd/hostveil || return 1
        done
    done
}

lint() {
    local cache=${XDG_CACHE_HOME:-$HOME/.cache}/hostveil
    local dir=$cache/golangci-lint-$LINT_VERSION-linux-amd64
    if [[ ! -x $dir/golangci-lint ]]; then
        mkdir -p "$cache" || return 1
        curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/v$LINT_VERSION/golangci-lint-$LINT_VERSION-linux-amd64.tar.gz" |
            tar xz -C "$cache" || return 1
    fi
    "$dir/golangci-lint" run ./...
}

site_clean() {
    go run ./cmd/sitegen >/dev/null && git diff --exit-code --stat site/
}

install_sum() {
    (cd scripts && sha256sum -c install.sh.sha256)
}

step build go build ./...
step vet go vet ./...
step gofmt gofmt_clean
step tidy tidy_clean
if $fast; then
    step test go test ./...
else
    step race go test -race ./...
    step cross-compile cross_compile
fi
step lint lint
step sitegen site_clean
step install.sh install_sum
step govulncheck go run "$GOVULNCHECK" ./...

# A distribution's Go reports a version like go1.26.5-X:nodwarf5, which
# govulncheck cannot parse, so it drops the standard library from the scan and
# still says "No vulnerabilities found".
if go version | grep -Eq 'go[0-9.]+-'; then
    printf 'note govulncheck did not scan the standard library on %s; CI does\n' "$(go version | awk '{print $3}')"
fi

if (( ${#failed[@]} > 0 )); then
    printf '\n%d step(s) failed: %s\n' "${#failed[@]}" "${failed[*]}"
    exit 1
fi
printf '\nall steps passed\n'
