#!/usr/bin/env bash
# Reset the hostveil test environment to a clean state.
# Usage: ./docker/reset.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "  hostveil test environment — reset"
echo ""

echo "  [1/3] Tearing down..."
docker compose down -v 2>/dev/null || true

echo "  [2/3] Building fresh image..."
docker compose build --no-cache

echo "  [3/3] Starting..."
docker compose up -d

echo ""
echo "  Ready. Run:"
echo "    cd docker && ./run.sh sh"
echo "    # Inside container:"
echo "    cd /hostveil && go build -o hostveil ./cmd/hostveil && ./hostveil serve --addr 0.0.0.0:8787"
echo ""
echo "  Then open http://localhost:8787"
