#!/usr/bin/env bash
# scripts/lab-tui.sh
# Run Hostveil TUI inside ttyd for web-based observation

set -euo pipefail

# Build hostveil if not built
if [[ ! -f target/debug/hostveil ]]; then
    echo "Building hostveil..."
    cargo build
fi

# Run ttyd with hostveil
echo "Starting ttyd on port 7681..."
echo "Open your browser to see the TUI."
ttyd -p 7681 ./target/debug/hostveil "$@"
