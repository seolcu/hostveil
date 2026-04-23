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
    local scenario_dir="$SCENARIOS_DIR/$name"
    local temp_dir
    temp_dir=$(mktemp -d)
    
    cp "$scenario_dir/docker-compose.yml" "$temp_dir/docker-compose.yml"
    
    echo "Testing scenario: $name"
    
    # Run Hostveil fix in non-interactive mode
    $BINARY_PATH --fix "$temp_dir/docker-compose.yml" --yes --user-mode > /dev/null
    
    # Compare with expected
    if diff -u "$scenario_dir/expected.yml" "$temp_dir/docker-compose.yml"; then
        echo "✅ Scenario '$name' passed!"
        rm -rf "$temp_dir"
        return 0
    else
        echo "❌ Scenario '$name' failed! See diff above."
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
    run_scenario "$scenario" || failed=1
done

exit $failed
