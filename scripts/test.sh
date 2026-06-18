#!/usr/bin/env bash
# Test runner for hostveil. Three layers:
#   - unit:        always
#   - contract:    always (no external dependencies)
#   - integration: requires HOSTVEIL_INTEGRATION=1 (needs Docker for the test host)
set -euo pipefail

cd "$(dirname "$0")/.."

run_unit() {
  echo "==> unit tests"
  go test ./... -count=1 -timeout=120s
}

run_contract() {
  echo "==> contract tests"
  go test ./tests/contract/... -count=1 -timeout=120s
}

run_integration() {
  echo "==> integration tests (HOSTVEIL_INTEGRATION=1)"
  if [[ "${HOSTVEIL_INTEGRATION:-0}" != "1" ]]; then
    echo "skipping; set HOSTVEIL_INTEGRATION=1 to enable"
    return 0
  fi
  go test ./tests/integration/... -count=1 -timeout=600s
}

run_perf() {
  echo "==> performance budget tests (HOSTVEIL_PERF=1)"
  if [[ "${HOSTVEIL_PERF:-0}" != "1" ]]; then
    echo "skipping; set HOSTVEIL_PERF=1 to enable"
    return 0
  fi
  go test ./tests/integration/... -count=1 -timeout=1800s -run TestPerf
}

run_unit
run_contract
run_integration
run_perf
