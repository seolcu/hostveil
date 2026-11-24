#!/usr/bin/env bash
# Provision a vulnerable Ubuntu 24.04 "home server" for the
# Hostveil demo. Runs as root via Vagrant's shell provisioner. Everything
# here is REAL (real Docker, real running stacks, real weak configs) so
# every Hostveil domain fires authentically.
set -euo pipefail

REPO=/hostveil                 # synced folder → repo root
DEMO="$REPO/demo"
GO_VERSION=1.26.3
export DEBIAN_FRONTEND=noninteractive

echo "==> [0/10] prefer IPv4 (libvirt NAT usually has no IPv6 egress → apt/curl/docker fail on IPv6)"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

echo "==> [1/10] base packages"
apt-get update -y || true
apt-get install -y ca-certificates curl git ufw openssh-server

echo "==> [2/10] Docker (official convenience script: gives 'docker compose')"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
# Root only: vagrant is not in the docker group, so dockerd.group-members
# has nothing to report and every docker command here and in run.sh is sudo.
#
# The daemon gets one setting a careful operator adds, no-new-privileges.
# live-restore and userns-remap are left at Docker's defaults:
# dockerd.live-restore is Auto (a reload turns it on, see internal/fix
# dockerd.go) and dockerd.userns-remap stays the one daemon finding a person
# decides, because it moves every image and container into new storage.
install -d /etc/docker
printf '{\n  "no-new-privileges": true\n}\n' > /etc/docker/daemon.json
systemctl enable --now docker
systemctl restart docker

echo "==> [3/10] Go ${GO_VERSION} (apt's Go is too old to build Hostveil)"
ARCH=$(dpkg --print-architecture)     # amd64 | arm64
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
fi
export PATH="$PATH:/usr/local/go/bin"

echo "==> [4/10] Trivy (optional CVE scanner) + vuln DB"
# NOTE: this provisioner runs as root, so --download-db-only warms only
# /root/.cache/trivy. A non-root `hostveil` scan uses ~vagrant/.cache/trivy and
# will download the DB itself on first use.
if ! command -v trivy >/dev/null 2>&1; then
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin
fi
trivy image --download-db-only 2>/dev/null || echo "   (trivy DB download skipped: CVE scan will fetch on first run)"

echo "==> [5/10] weak SSH config (a drop-in that outranks the image's own)"
# The seed goes in sshd_config.d, because
# the main file loses. Ubuntu's sshd_config puts `Include
# sshd_config.d/*.conf` at the top and sshd keeps the first value it
# obtains for each keyword, so the cloud image's 50-cloud-init.conf and
# 60-cloudimg-settings.conf (both of which set PasswordAuthentication no)
# beat anything appended below. Appending is what this script used to do,
# and it left ssh.passwordauth silently unreproducible.
#
# The 00- prefix sorts ahead of the image's drop-ins, so these win. That
# also makes the demo exercise the checker's Include handling.
install -m 0644 "$DEMO/seed/sshd_hostveil.conf" /etc/ssh/sshd_config.d/00-hostveil-demo.conf

# Converge VMs provisioned by the older version of this script, which
# appended the same settings to the main file and left them there.
if grep -q "hostveil demo weak SSH" /etc/ssh/sshd_config; then
  sed -i '/# --- hostveil demo weak SSH/,$d' /etc/ssh/sshd_config
fi

sshd -t && (systemctl restart ssh || systemctl restart sshd || true)

echo "==> [6/10] disable automatic security updates (updates.disabled)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
# The firewall is on, allowing SSH, and Docker publishes the stacks' ports
# around it: Docker writes its own rules ahead of ufw's, so a port ufw does
# not allow is still reachable (firewall.docker-bypass). Binding the ports to
# 127.0.0.1 (the compose fixes) closes it.
ufw allow 22/tcp >/dev/null
ufw --force enable

echo "==> [7/10] host: what a careful install already has, and what a hurried one changed"
# Everything here is sound, so the scan reports only what the next
# paragraph seeds. The updates domain checks for these tools, and the
# security updates themselves are installed now (the VM has no internet at
# the booth, so the list it sees stays the one from today).
apt-get install -y --no-install-recommends \
  auditd fail2ban debsums rkhunter apt-listchanges apt-show-versions acct \
  libpam-pwquality libpam-tmpdir sysstat
# full-upgrade, with phased updates: a plain upgrade holds back a new kernel
# and whatever Ubuntu is phasing in, and updates.pending-security reports
# both. homelab setup boots the new kernel.
apt-get -y -o Dpkg::Options::=--force-confold \
  -o APT::Get::Always-Include-Phased-Updates=true full-upgrade
printf 'Authorized access only. Unauthorized access is prohibited and monitored.\n' > /etc/issue
cp /etc/issue /etc/issue.net
# The assembler and linker came in with the toolchain packages; a server
# keeps them to administrators (fileperms.compiler).
chmod 0750 /usr/bin/*-linux-gnu-as /usr/bin/*-linux-gnu-ld.bfd /usr/bin/*-linux-gnu-ld.gold 2>/dev/null || true
# Not a router, so it sends no ICMP redirects. Docker turns on forwarding,
# which is why sysctl.send-redirects stays a Review finding on a Docker host
# instead of being settled from ip_forward.
printf 'net.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n' > /etc/sysctl.d/60-local-net.conf
sysctl -p /etc/sysctl.d/60-local-net.conf >/dev/null || true
# No USB drives on this box.
printf 'install usb-storage /bin/false\n' > /etc/modprobe.d/blacklist-usb-storage.conf

# What the hurried install changed, every one of them fixed by
# `hostveil fix --all`:
#
# /etc/shadow made world-readable → fileperms.shadow (every password hash).
chmod 0644 /etc/shadow || true

# Two sysctl overrides that fight Ubuntu's own hardened defaults.
# ptrace_scope=0 and perf_event_paranoid<2 are among the most-copied lines in
# "gdb: Operation not permitted" and "perf: Permission denied" guides, dropped
# in sysctl.d to survive a reboot. → sysctl.ptrace-scope, sysctl.perf-events
cat > /etc/sysctl.d/98-local.conf <<'EOF2'
kernel.yama.ptrace_scope = 0
kernel.perf_event_paranoid = -1
EOF2
sysctl -p /etc/sysctl.d/98-local.conf >/dev/null || true

echo "==> [8/10] self-hosted AI agent runtime configs (OpenClaw + Hermes)"
# NOTE: neither project is packaged for apt, and neither ships a daemon we
# could accurately run here, so this seeds their *configuration* only. That is enough for the agent domain: Hostveil detects a
# runtime by its home-directory layout and judges the config and file modes,
# which is exactly the ground these fixtures cover.
#
# The one thing it cannot show is the listener cross-check. The finding is
# High either way (the firewall and the listener decide the confidence, not
# the level, and both ride in the evidence) but with nothing bound to
# :18789 the evidence says the binding came from the config. To see the other case in the demo, run something on
# the port first:  python3 -m http.server 18789 --bind 0.0.0.0 &
install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.openclaw
install -d -m 0755 -o vagrant -g vagrant /home/vagrant/.openclaw/credentials  # too open → agent.secret-exposed
install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.openclaw/state
install -m 0644 -o vagrant -g vagrant "$DEMO/seed/openclaw.json" /home/vagrant/.openclaw/openclaw.json  # → agent.config-perms

install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.hermes
install -m 0644 -o vagrant -g vagrant "$DEMO/seed/hermes.env" /home/vagrant/.hermes/.env  # → agent.secret-exposed

echo "==> [9/10] deploy the compose stacks"
mkdir -p /opt/stacks
cp -r "$DEMO/stacks/." /opt/stacks/
# Bring the stacks up once now. They have no restart policy, so
# they do NOT come back on their own after a reboot: nothing auto-starts.
# Use `demo/run.sh up` on the host to start the demo whenever you want it.
for dir in /opt/stacks/*/; do
  name=$(basename "$dir")
  echo "   • bringing up stack: $name"
  ( cd "$dir" && docker compose up -d --build ) \
    || echo "     (stack '$name' had a service that failed to start; Hostveil still audits its compose file)"
done

echo "==> [10/10] build Hostveil from the mounted source"
cd "$REPO"
GOFLAGS=-buildvcs=false /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil
hostveil version || true

cat <<'BANNER'

============================================================
  Hostveil demo host is ready.

  Try it (SSH in first with:  vagrant ssh):
    sudo hostveil scan                 # scored findings across all domains
    sudo hostveil                      # interactive TUI
    sudo hostveil fix ssh.rootlogin    # preview + apply a fix
    sudo hostveil rollback <id>        # undo it
    sudo hostveil web                  # web UI (reach it with: ssh homelab)

  Reset to the pristine vulnerable state between demos:
    (on the host)  ./homelab reset
============================================================
BANNER
