#!/bin/bash
set -e

export HOSTVEIL_TEST=1

echo "=== hostveil test environment ==="

# ── 1. Start Docker daemon ──
echo "[1/4] Starting Docker daemon..."
/usr/local/bin/dockerd-entrypoint.sh &
DOCKER_PID=$!

until docker info >/dev/null 2>&1; do sleep 0.5; done
echo "      ready."

# ── 2. Apply kernel-level vulnerabilities ──
echo "[2/4] Applying kernel vulnerabilities..."
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || true
sysctl -w net.ipv4.tcp_syncookies=0 2>/dev/null || true

# ── 3. Start SSH daemon ──
echo "[3/4] Starting SSH..."
/usr/sbin/sshd &
SSHD_PID=$!

# ── 4. Start test Compose projects ──
echo "[4/4] Starting Compose projects..."
if [ -d /opt/compose/vuln-project ]; then
    cd /opt/compose/vuln-project
    docker compose pull 2>/dev/null || true
    docker compose up -d 2>/dev/null || echo "      (compose skipped — images may need pulling on first run)"

    echo "      Verifying compose projects..."
    for i in {1..10}; do
      docker compose ps --status running 2>/dev/null | grep -q "Up" && break
      sleep 1
    done
fi

echo ""
echo "  Ready. Run hostveil:"
echo "    cd /hostveil && go build -o hostveil ./cmd/hostveil && ./hostveil serve --addr 0.0.0.0:8787"
echo "    cd /hostveil && go build -o hostveil ./cmd/hostveil && ./hostveil tui-web --addr 0.0.0.0:8787"
echo ""

wait $DOCKER_PID
sleep infinity
