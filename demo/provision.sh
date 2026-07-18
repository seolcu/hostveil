#!/usr/bin/env bash
# Provision a deliberately vulnerable Ubuntu 24.04 "home server" for the
# hostveil demo. Runs as root via Vagrant's shell provisioner. Everything
# here is REAL — real Docker, real running stacks, real weak configs — so
# every hostveil domain fires authentically.
set -euo pipefail

REPO=/hostveil                 # synced folder → repo root
DEMO="$REPO/demo"
GO_VERSION=1.26.3
export DEBIAN_FRONTEND=noninteractive

echo "==> [0/8] prefer IPv4 (libvirt NAT usually has no IPv6 egress → apt/curl/docker fail on IPv6)"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

echo "==> [1/8] base packages"
apt-get update -y || true
apt-get install -y ca-certificates curl git ufw openssh-server

echo "==> [2/8] Docker (official convenience script — gives 'docker compose')"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
usermod -aG docker vagrant || true   # so `docker ps` works without sudo in the demo

echo "==> [3/8] Go ${GO_VERSION} (apt's Go is too old to build hostveil)"
ARCH=$(dpkg --print-architecture)     # amd64 | arm64
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH="$PATH:/usr/local/go/bin"

echo "==> [4/8] Trivy (optional CVE scanner) + vuln DB"
if ! command -v trivy >/dev/null 2>&1; then
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin
fi
trivy image --download-db-only 2>/dev/null || echo "   (trivy DB download skipped — CVE scan will fetch on first run)"

echo "==> [5/8] weak SSH config (appended to the main sshd_config)"
if ! grep -q "hostveil demo weak SSH" /etc/ssh/sshd_config; then
  {
    echo ""
    echo "# --- hostveil demo weak SSH (intentionally insecure) ---"
    cat "$DEMO/seed/sshd_hostveil.conf"
  } >> /etc/ssh/sshd_config
fi
systemctl restart ssh || systemctl restart sshd || true

echo "==> [6/8] disable automatic security updates (so updates.disabled fires)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
# ufw is installed but left INACTIVE → firewall.inactive fires.
ufw --force disable || true

echo "==> [7/8] deploy vulnerable compose stacks"
mkdir -p /opt/stacks
cp -r "$DEMO/stacks/." /opt/stacks/
for dir in /opt/stacks/*/; do
  name=$(basename "$dir")
  echo "   • bringing up stack: $name"
  ( cd "$dir" && docker compose pull -q 2>/dev/null; docker compose up -d ) \
    || echo "     (stack '$name' had a service that failed to start — hostveil still audits its compose file)"
done

echo "==> [8/8] build hostveil from the mounted source"
cd "$REPO"
GOFLAGS=-buildvcs=false /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil
hostveil version || true

cat <<'BANNER'

============================================================
  hostveil demo host is ready — a vulnerable Ubuntu server.

  Try it (SSH in first with:  vagrant ssh):
    sudo hostveil scan                 # scored findings across all domains
    sudo hostveil                      # interactive TUI
    sudo hostveil fix ssh.rootlogin    # preview + apply a fix
    sudo hostveil rollback <id>        # undo it
    sudo hostveil serve --addr 0.0.0.0:8787   # web UI → http://localhost:8787

  Reset to the pristine vulnerable state between demos:
    (on the host)  vagrant snapshot restore clean
============================================================
BANNER
