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

echo "==> [0/10] prefer IPv4 (libvirt NAT usually has no IPv6 egress → apt/curl/docker fail on IPv6)"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
echo 'Acquire::ForceIPv4 "true";' > /etc/apt/apt.conf.d/99force-ipv4

echo "==> [1/10] base packages"
apt-get update -y || true
apt-get install -y ca-certificates curl git ufw openssh-server

echo "==> [2/10] Docker (official convenience script — gives 'docker compose')"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
usermod -aG docker vagrant || true   # so `docker ps` works without sudo in the demo

# --- hostveil demo: a deliberately dangerous Docker daemon -----------------
# This is the real thing, not a mock: an unauthenticated Docker API on 2375
# is root on this VM for anyone who can reach the port, and a 0666 socket is
# root for any local account. It is acceptable here only because the
# Vagrantfile NATs this VM and forwards nothing to 2375 — check that before
# adding a forwarded port. Everything below is undone by `./run.sh reset`.
#
# Seeded before the stacks come up in [9/10], so the daemon restart does not
# bounce them.

# dockerd.api-unauthenticated (High). The drop-in is generated from the
# CURRENT ExecStart rather than hardcoded, so it survives Docker changing its
# packaged flags. The bare `ExecStart=` line is mandatory: without it systemd
# rejects a second ExecStart on a Type=notify service. And the socket goes
# here rather than into daemon.json's "hosts" — dockerd refuses to start when
# that key and -H are both set, and -H fd:// is already on the shipped unit.
install -d /etc/systemd/system/docker.service.d
CURRENT_EXECSTART=$(systemctl show docker.service -p ExecStart --value \
  | sed -n 's/.*argv\[\]=\([^;]*\).*/\1/p')
printf '[Service]\nExecStart=\nExecStart=%s -H tcp://0.0.0.0:2375\n' \
  "${CURRENT_EXECSTART:-/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock}" \
  > /etc/systemd/system/docker.service.d/10-hostveil-demo.conf

# dockerd.socket-world-writable (High). Set on the socket unit, not with
# chmod: dockerd recreates the socket from this unit at every start, so a
# chmod would be gone by the time hostveil looked — and the unit drop-in is
# the misconfiguration people actually make.
install -d /etc/systemd/system/docker.socket.d
printf '[Socket]\nSocketMode=0666\n' \
  > /etc/systemd/system/docker.socket.d/10-hostveil-demo.conf

systemctl daemon-reload
systemctl restart docker.socket || true
systemctl restart docker

# dockerd.group-members escalates Medium -> High when a service account holds
# the group. vagrant above gives the Medium; a CI runner that cannot log in
# and can still become root is the case worth showing.
id ci_runner >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin ci_runner
usermod -aG docker ci_runner || true

# no-new-privileges, userns-remap and live-restore need no seeding: all three
# are off by default on a stock install, which is the point of the rules.
# dockerd.api-tls-unverified is not seeded — it needs a server keypair, which
# is more machinery than the demo earns. Unit tests cover it.

echo "==> [3/10] Go ${GO_VERSION} (apt's Go is too old to build hostveil)"
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
trivy image --download-db-only 2>/dev/null || echo "   (trivy DB download skipped — CVE scan will fetch on first run)"

echo "==> [5/10] weak SSH config (a drop-in that outranks the image's own)"
# The seed goes in sshd_config.d, not at the end of the main file, because
# the main file loses. Ubuntu's sshd_config puts `Include
# sshd_config.d/*.conf` at the top and sshd keeps the first value it
# obtains for each keyword, so the cloud image's 50-cloud-init.conf and
# 60-cloudimg-settings.conf — both of which set PasswordAuthentication no —
# beat anything appended below. Appending is what this script used to do,
# and it left ssh.passwordauth silently unreproducible.
#
# The 00- prefix sorts ahead of the image's drop-ins, so these win. That
# also makes the demo exercise the checker's Include handling rather than
# only its main-file parsing.
install -m 0644 "$DEMO/seed/sshd_hostveil.conf" /etc/ssh/sshd_config.d/00-hostveil-demo.conf

# Converge VMs provisioned by the older version of this script, which
# appended the same settings to the main file and left them there.
if grep -q "hostveil demo weak SSH" /etc/ssh/sshd_config; then
  sed -i '/# --- hostveil demo weak SSH/,$d' /etc/ssh/sshd_config
fi

sshd -t && (systemctl restart ssh || systemctl restart sshd || true)

echo "==> [6/10] disable automatic security updates (so updates.disabled fires)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
# ufw is installed but left INACTIVE → firewall.inactive fires.
ufw --force disable || true

echo "==> [7/10] host-level weaknesses (native exposed service, weak accounts, loose file perms, sysctl, systemd)"
# A NON-Docker datastore bound to every interface → ports.exposed-datastore.
# This is exactly the kind of exposure a Compose-file audit can never see,
# because it is a native service, not a container.
apt-get install -y redis-server
sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf || true
sed -i 's/^protected-mode .*/protected-mode no/' /etc/redis/redis.conf || true
systemctl enable --now redis-server || true
systemctl restart redis-server || true

# A second account with root's UID (0) → accounts.uid0 (a classic backdoor).
# Named "breakglass": a real, common mistake, not a hacker's — an emergency
# admin account an ops team makes root-equivalent for out-of-band access and
# then never locks back down.
id breakglass >/dev/null 2>&1 || useradd -o -u 0 -g 0 -M -s /bin/bash breakglass

# A login account with no password at all → accounts.emptypassword.
# Named "contractor": a temp account made for an external contractor, its
# password cleared during onboarding "just to get them in", never set or
# removed afterward.
id contractor >/dev/null 2>&1 || useradd -m -s /bin/bash contractor
passwd -d contractor || true

# World-readable /etc/shadow → fileperms.shadow (every password hash exposed).
chmod 0644 /etc/shadow || true

# Two sysctl overrides that fight Ubuntu's own hardened defaults, not two
# that were merely left alone. ptrace_scope=0 and perf_event_paranoid<2 are
# among the most-copied lines in "gdb: Operation not permitted" and
# "perf: Permission denied" troubleshooting guides — self-hosters running a
# game server, profiling a stuck daemon, or following a flamegraph tutorial
# apply both and, to survive a reboot, drop them in sysctl.d. This is an
# operator actively undoing a default, which is the case worth showing —
# most of the sysctl domain's other rules already match Ubuntu's shipped
# 50-default.conf and would need a much less plausible edit to trip.
# → sysctl.ptrace-scope, sysctl.perf-events
cat > /etc/sysctl.d/98-local.conf <<'EOF'
kernel.yama.ptrace_scope = 0
kernel.perf_event_paranoid = -1
EOF
sysctl -p /etc/sysctl.d/98-local.conf >/dev/null || true

# A hand-written systemd unit with none of the sandboxing directives —
# exactly what copying a tutorial's minimal [Unit]/[Service]/[Install]
# skeleton for a backup script produces, and one of the most common ways a
# self-hoster ends up with an *operator* unit (as opposed to a
# distro-packaged one) in the first place.
# → the systemd domain's hardening rules (NoNewPrivileges, ProtectSystem, …)
cat > /usr/local/bin/backup-stacks.sh <<'EOF'
#!/bin/sh
set -eu
mkdir -p /var/backups
tar -czf /var/backups/stacks-$(date +%F).tar.gz -C /opt stacks 2>/dev/null || true
EOF
chmod 0755 /usr/local/bin/backup-stacks.sh
cat > /etc/systemd/system/stacks-backup.service <<'EOF'
[Unit]
Description=Back up /opt/stacks

[Service]
ExecStart=/usr/local/bin/backup-stacks.sh
EOF
cat > /etc/systemd/system/stacks-backup.timer <<'EOF'
[Unit]
Description=Daily backup of /opt/stacks

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now stacks-backup.timer || true
systemctl start stacks-backup.service || true

echo "==> [8/10] self-hosted AI agent runtime configs (OpenClaw + Hermes)"
# NOTE: neither project is packaged for apt, and neither ships a daemon we
# could honestly run here, so this seeds their *configuration* rather than
# installing them. That is enough for the agent domain: hostveil detects a
# runtime by its home-directory layout and judges the config and file modes,
# which is exactly the ground these fixtures cover.
#
# The one thing it cannot show is the listener cross-check. The finding is
# High either way — the firewall and the listener decide the confidence, not
# the level, and both ride in the evidence — but with nothing bound to
# :18789 the evidence says the binding came from the config rather than from
# an observed socket. To see the other case in the demo, run something on
# the port first:  python3 -m http.server 18789 --bind 0.0.0.0 &
install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.openclaw
install -d -m 0755 -o vagrant -g vagrant /home/vagrant/.openclaw/credentials  # too open → agent.secret-exposed
install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.openclaw/state
install -m 0644 -o vagrant -g vagrant "$DEMO/seed/openclaw.json" /home/vagrant/.openclaw/openclaw.json  # → agent.config-perms

install -d -m 0700 -o vagrant -g vagrant /home/vagrant/.hermes
install -m 0644 -o vagrant -g vagrant "$DEMO/seed/hermes.env" /home/vagrant/.hermes/.env  # → agent.secret-exposed

echo "==> [9/10] deploy vulnerable compose stacks"
mkdir -p /opt/stacks
cp -r "$DEMO/stacks/." /opt/stacks/
# Bring the stacks up once now. They have no restart policy on purpose, so
# they do NOT come back on their own after a reboot — nothing auto-starts.
# Use `demo/run.sh up` on the host to start the demo whenever you want it.
for dir in /opt/stacks/*/; do
  name=$(basename "$dir")
  echo "   • bringing up stack: $name"
  ( cd "$dir" && docker compose pull -q 2>/dev/null; docker compose up -d ) \
    || echo "     (stack '$name' had a service that failed to start — hostveil still audits its compose file)"
done

echo "==> [10/10] build hostveil from the mounted source"
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
