#!/usr/bin/env bash
# Put a throwaway host into the `seeded` profile — the deliberately
# misconfigured self-hosted server the published measurements were taken on.
#
#   scripts/measure/seed.sh [--user NAME] [--no-instruments] [--force]
#   scripts/measure/run.sh -c -p seeded /tmp/measurement.json
#
# This exists because the measurements page told a reader to clone the repo and
# run the harness, and the harness measures whatever host it is pointed at. The
# seeding lived in a script nobody could see, so the published figures were not
# reproducible by the instructions published beside them — and the fixture drifted
# from the product without anything noticing: an earlier copy of it wrote the
# OpenClaw config to ~/.config/openclaw/, which is not a path the agent checker
# scans, so the domain reported "no agent runtime found" on a host seeded to have
# two. internal/docs/seed_test.go now holds every path here against the checker.
#
# The fixtures are demo/seed/ and demo/stacks/, shared with the Vagrant demo, so
# there is one description of this host rather than two that disagree.
#
# IT EDITS THE HOST IT RUNS ON, destructively and without a way back: it opens
# an SSH drop-in, adds a second UID 0 account, world-reads /etc/shadow, and
# publishes datastores on 0.0.0.0. Use a container or a VM you are willing to
# throw away. It refuses to run anywhere that does not look like one unless
# --force says otherwise.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DEMO="$REPO/demo"

SEED_USER=root
INSTRUMENTS=1
FORCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --user) SEED_USER=$2; shift 2 ;;
    --no-instruments) INSTRUMENTS=0; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "seed: unknown argument $1" >&2; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }

[ "$(id -u)" = 0 ] || { echo "seed: needs root" >&2; exit 1; }

# The guard is not security, it is a speed bump in front of an irreversible
# script. A container or a VM is the intended target; anything else is very
# likely somebody's actual machine.
disposable() {
  [ -f /.dockerenv ] && return 0
  [ -n "${container:-}" ] && return 0
  grep -qa 'container=lxc\|container=docker' /proc/1/environ 2>/dev/null && return 0
  command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt)" != none ] && return 0
  return 1
}
if [ "$FORCE" = 0 ] && ! disposable; then
  cat >&2 <<'WARN'
seed: this does not look like a container or a VM.

This script is destructive and has no undo: it permits root SSH login and empty
passwords, adds a second account with UID 0, makes /etc/shadow world-readable,
and publishes databases on every interface. Do not run it on a machine you care
about.

Pass --force if you are sure.
WARN
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

SEED_HOME=$(getent passwd "$SEED_USER" | cut -d: -f6)
[ -n "$SEED_HOME" ] || { echo "seed: no such user: $SEED_USER" >&2; exit 1; }

say "base packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl git ufw openssh-server sudo iproute2 \
  systemd-sysv python3 jq >/dev/null

say "docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh >/dev/null 2>&1
fi
systemctl enable --now docker >/dev/null 2>&1 || true
docker version --format '{{.Server.Version}}' 2>&1 | tail -1

say "weak SSH — a drop-in that outranks the image's own"
# Ubuntu's sshd_config includes sshd_config.d/*.conf at the top and sshd keeps
# the FIRST value it obtains for each keyword, so the cloud image's own
# drop-ins beat anything appended to the main file. The 00- prefix sorts ahead
# of them. This also makes the fixture exercise the checker's Include handling
# rather than only its main-file parsing.
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$DEMO/seed/sshd_hostveil.conf" /etc/ssh/sshd_config.d/00-hostveil-demo.conf
systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true

say "firewall installed and left off, automatic updates off"
ufw --force disable >/dev/null 2>&1 || true
systemctl disable --now unattended-upgrades >/dev/null 2>&1 || true
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF

say "host-level weaknesses — a native datastore on 0.0.0.0, a uid-0 twin, loose perms"
# A NON-Docker datastore on every interface. This is the exposure a Compose
# audit can never see, and the one hostveil reports and declines to fix,
# because the config path differs per datastore.
apt-get install -y -qq redis-server >/dev/null 2>&1 || true
sed -i 's/^bind .*/bind 0.0.0.0/; s/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf 2>/dev/null || true
systemctl enable --now redis-server >/dev/null 2>&1 \
  || redis-server /etc/redis/redis.conf --daemonize yes >/dev/null 2>&1 || true

id backdoor >/dev/null 2>&1 || useradd -o -u 0 -g 0 -M -s /bin/bash backdoor
id demo_nopass >/dev/null 2>&1 || useradd -m -s /bin/bash demo_nopass
passwd -d demo_nopass >/dev/null 2>&1 || true
chmod 0644 /etc/shadow

say "AI agent runtime configs (OpenClaw + Hermes) under $SEED_HOME"
# Neither project is packaged, and neither ships a daemon this could honestly
# run, so this seeds their *configuration*. That is what the agent domain
# judges: a runtime is detected by its home-directory layout, and the findings
# are about the config's contents and the file modes around it.
#
# The paths are load-bearing and are pinned by internal/docs/seed_test.go
# against internal/check/agent's own runtime table. A fixture that writes
# somewhere the checker does not look produces "no agent runtime found" on a
# host seeded to have two, and reads as a clean domain rather than a broken
# fixture.
install -d -m 0700 -o "$SEED_USER" -g "$SEED_USER" "$SEED_HOME/.openclaw"
install -d -m 0755 -o "$SEED_USER" -g "$SEED_USER" "$SEED_HOME/.openclaw/credentials"
install -d -m 0700 -o "$SEED_USER" -g "$SEED_USER" "$SEED_HOME/.openclaw/state"
install -m 0644 -o "$SEED_USER" -g "$SEED_USER" "$DEMO/seed/openclaw.json" "$SEED_HOME/.openclaw/openclaw.json"

install -d -m 0700 -o "$SEED_USER" -g "$SEED_USER" "$SEED_HOME/.hermes"
install -m 0644 -o "$SEED_USER" -g "$SEED_USER" "$DEMO/seed/hermes.env" "$SEED_HOME/.hermes/.env"

say "compose stacks"
install -d -m 0755 /opt/stacks
cp -r "$DEMO/stacks/." /opt/stacks/
chmod -R 0777 /opt/stacks
for dir in /opt/stacks/*/; do
  name=$(basename "$dir")
  echo "  -- $name"
  ( cd "$dir" && timeout 900 docker compose up -d 2>&1 | tail -2 ) \
    || echo "     (a service did not start; its compose file is still audited)"
done

if [ "$INSTRUMENTS" = 1 ]; then
  say "the instruments the harness reports through"
  # Absent ones are recorded as absent rather than passed over, so this is a
  # convenience — but a run missing one is a run missing a whole column, and
  # the CVE domain being absent also *raises* the score, because an excluded
  # axis leaves the denominator rather than scoring zero.
  apt-get install -y -qq lynis >/dev/null 2>&1 || echo "  lynis: install failed"
  if [ ! -x /opt/docker-bench-security/docker-bench-security.sh ]; then
    git clone -q --depth 1 https://github.com/docker/docker-bench-security.git \
      /opt/docker-bench-security || echo "  docker-bench: clone failed"
  fi
  chmod +x /opt/docker-bench-security/docker-bench-security.sh 2>/dev/null || true
  if ! command -v trivy >/dev/null 2>&1; then
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin >/dev/null 2>&1 || echo "  trivy: install failed"
  fi
  trivy image --download-db-only >/dev/null 2>&1 || true
fi

say "seeded — what the harness will find"
printf '  %-14s %s\n' \
  "lynis" "$(command -v lynis || echo 'MISSING — no hardening index column')" \
  "docker-bench" "$(test -x /opt/docker-bench-security/docker-bench-security.sh && echo ok || echo 'MISSING — no CIS column')" \
  "trivy" "$(command -v trivy || echo 'MISSING — CVE axis N/A, and the score reads higher for it')" \
  "hostveil" "$(command -v hostveil || echo 'MISSING — build it: go build -o /usr/local/bin/hostveil ./cmd/hostveil')" \
  "containers" "$(docker ps -q 2>/dev/null | wc -l)"

cat <<'NEXT'

Next:
  go build -o /usr/local/bin/hostveil ./cmd/hostveil
  scripts/measure/run.sh -c -p seeded /tmp/measurement.json

run.sh applies every fix and then rolls them all back, so it leaves this host
roughly as this script left it — roughly, because enabling a firewall and
installing unattended-upgrades are not file edits and have no checkpoint. Seed
again rather than measuring twice on one host.
NEXT
