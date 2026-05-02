#!/usr/bin/env bash
# scripts/verify-fixes.sh
# Automate Scan -> Fix -> Verify loop for Hostveil remediation logic

set -euo pipefail

BINARY_PATH="${1:-./target/debug/hostveil}"
SCENARIOS_DIR="tests/scenarios"

if [[ ! -x "$BINARY_PATH" ]]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

run_scenario() {
    local name=$1
    local mode=$2
    local scenario_dir="$SCENARIOS_DIR/$name"
    local temp_dir
    temp_dir=$(mktemp -d)

    cp "$scenario_dir/docker-compose.yml" "$temp_dir/docker-compose.yml"

    echo "Testing scenario: $name (mode: $mode)"

    # Run Hostveil fix in non-interactive mode
    $BINARY_PATH --$mode "$temp_dir/docker-compose.yml" --yes --user-mode > /dev/null

    # Determine expected file: mode-specific if present, else default
    local expected_file="$scenario_dir/expected.yml"
    if [[ "$mode" == "quick-fix" && -f "$scenario_dir/expected-quick-fix.yml" ]]; then
        expected_file="$scenario_dir/expected-quick-fix.yml"
    fi

    # Compare with expected
    if diff -u "$expected_file" "$temp_dir/docker-compose.yml"; then
        echo "✅ Scenario '$name' ($mode) passed!"
        rm -rf "$temp_dir"
        return 0
    else
        echo "❌ Scenario '$name' ($mode) failed! See diff above."
        rm -rf "$temp_dir"
        return 1
    fi
}

failed=0
for scenario in $(ls "$SCENARIOS_DIR"); do
    # Skip if expected.yml doesn't exist
    if [[ ! -f "$SCENARIOS_DIR/$scenario/expected.yml" ]]; then
        continue
    fi

    # Always test full --fix
    run_scenario "$scenario" "fix" || failed=1

    # Also test --quick-fix if a quick-fix expected file exists
    if [[ -f "$SCENARIOS_DIR/$scenario/expected-quick-fix.yml" ]]; then
        run_scenario "$scenario" "quick-fix" || failed=1
    fi
done

exit $failed
