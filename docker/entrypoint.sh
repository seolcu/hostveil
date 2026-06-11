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
sysctl -w net.ipv4.conf.all.accept_source_route=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.send_redirects=1 2>/dev/null || true
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true

# ── 3. Start SSH daemon ──
echo "[3/4] Starting SSH..."
/usr/sbin/sshd &
SSHD_PID=$!

# ── 4. Start test Compose projects ──
echo "[4/4] Starting Compose projects..."
for project in vuln-project overprivileged; do
    if [ -d "/opt/compose/$project" ]; then
        cd "/opt/compose/$project"
        echo "      pulling images for $project..."
        docker compose pull 2>&1 || echo "      ⚠ $project pull failed — continuing"
        echo "      starting $project..."
        docker compose up -d 2>&1 || echo "      ⚠ $project up failed — continuing"
    fi
done

# Verify at least one project is running
echo "      checking compose projects..."
for i in {1..15}; do
  running=$(docker compose ls --filter name=hostveil 2>&1 | wc -l || true)
  if [ "$running" -ge 1 ]; then
    break
  fi
  sleep 1
done
docker compose ls --filter name=hostveil 2>&1 || true

echo ""
echo "  Ready. Run hostveil:"
echo "    cd /hostveil && go build -o hostveil ./cmd/hostveil && ./hostveil serve --addr 0.0.0.0:8787"
echo "    cd /hostveil && go build -o hostveil ./cmd/hostveil && ./hostveil tui-web --addr 0.0.0.0:8787"
echo ""

wait $DOCKER_PID
sleep infinity
