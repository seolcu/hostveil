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

# --- what this host was actually made to look like -------------------------
#
# The measurement is only comparable across distributions if the fixture means
# the same thing on each of them, and it cannot always: Alpine has no
# unattended-upgrades and nothing that stands in for it, so a host seeded there
# has no "automatic updates are switched off" weakness to find. The number that
# comes back is then higher for a reason that has nothing to do with hostveil.
#
# That is the same failure this whole project is built against — an absence
# read as an all-clear — so it is recorded rather than left to be inferred from
# a score. Every weakness declares itself as it is seeded, the manifest goes
# where run.sh can put it in the measurement JSON, and a `require` that does
# not arrive stops the script instead of producing a host nobody can interpret.
MANIFEST=${SEED_MANIFEST:-/var/lib/hostveil-measure/seeded.json}
DOCKER_BENCH_REV=154869da6418089decf7e1ab0cfca0e1cdfc5c49
TRIVY_INSTALL_REV=dcbadb7b15076c405ce7d59f04cde9991b90da22
SEEDED=()
MISSING=()

seeded() { SEEDED+=("$1"); }

# unseedable records a weakness this distribution cannot express, with the
# reason. It is not a failure — it is the difference between two hosts, which
# is exactly what a cross-distribution measurement is for.
unseedable() {
  MISSING+=("$1|$2")
  printf '  -- %s: not seeded on %s (%s)\n' "$1" "$DISTRO_ID" "$2"
}

# require fails the run. Reserved for the weaknesses every supported
# distribution can express: if one of those is missing, the host is broken
# rather than different, and measuring it would report hostveil finding
# nothing on a host that was never made bad.
require() {
  local what=$1 && shift
  if "$@"; then
    seeded "$what"
  else
    echo "seed: could not seed $what on $DISTRO_ID — refusing to leave a host that cannot be measured" >&2
    exit 1
  fi
}

# The weaknesses, each named once and testable on its own. They are functions
# rather than inline `sh -c` strings so that what is being asserted reads as a
# sentence and shellcheck can see it.
have_docker()      { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }
have_weak_ssh()    { grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config.d/00-hostveil-demo.conf 2>/dev/null; }
have_firewall()    { command -v "$1" >/dev/null 2>&1; }
have_uid0_twin()   { awk -F: '$3 == 0 && $1 != "root"' /etc/passwd | grep -q .; }
have_open_shadow() { [ "$(stat -c %a /etc/shadow 2>/dev/null)" = 644 ]; }
have_agent_cfg()   { [ -f "$SEED_HOME/.openclaw/openclaw.json" ] && [ -f "$SEED_HOME/.hermes/.env" ]; }
have_stacks()      { ls /opt/stacks/*/docker-compose.y*ml >/dev/null 2>&1; }
have_exposed_redis() { ss -ltn 2>/dev/null | grep -qE '(0\.0\.0\.0|\*):6379'; }
have_debug_sysctl()  { [ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" = 0 ] \
                          && [ "$(sysctl -n kernel.perf_event_paranoid 2>/dev/null)" -lt 2 ] 2>/dev/null; }
have_unhardened_unit() { systemctl show stacks-backup.service -p LoadState --value 2>/dev/null | grep -q loaded; }

write_manifest() {
  local dir
  dir=$(dirname "$MANIFEST")
  mkdir -p "$dir"
  {
    printf '{\n  "distro": "%s",\n  "distro_like": "%s",\n' "$DISTRO_ID" "$DISTRO_LIKE"
    printf '  "instruments": {"docker_bench_revision": "%s", "trivy_installer_revision": "%s"},\n' \
      "$DOCKER_BENCH_REV" "$TRIVY_INSTALL_REV"
    printf '  "seeded": ['
    local first=1 item
    for item in ${SEEDED+"${SEEDED[@]}"}; do
      [ $first = 1 ] || printf ', '
      printf '"%s"' "$item"
      first=0
    done
    printf '],\n  "not_expressible": {'
    first=1
    for item in ${MISSING+"${MISSING[@]}"}; do
      [ $first = 1 ] || printf ', '
      printf '"%s": "%s"' "${item%%|*}" "${item#*|}"
      first=0
    done
    printf '}\n}\n'
  } > "$MANIFEST"
  say "manifest at $MANIFEST"
}

# --- the distribution seam -------------------------------------------------
#
# Everything below this line that touches a package manager, a service
# manager, or a config path goes through one of these. The script used to call
# apt-get and systemctl directly, which is why every published measurement was
# taken on Ubuntu: not a decision, just the only host the fixture could build.
DISTRO_ID=unknown
DISTRO_LIKE=""
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091 # read at runtime from the host being seeded
  . /etc/os-release
  DISTRO_ID=${ID:-unknown}
  DISTRO_LIKE=${ID_LIKE:-}
fi

case "$DISTRO_ID $DISTRO_LIKE" in
  *debian*|*ubuntu*) PKG=apt ;;
  *fedora*|*rhel*|*centos*) PKG=dnf ;;
  *alpine*) PKG=apk ;;
  *) echo "seed: unsupported distribution '$DISTRO_ID' — it needs an entry in the distro seam" >&2; exit 1 ;;
esac

# Alpine runs OpenRC, which is not a smaller systemd: it has no unit files, so
# hostveil's systemd domain skips there and the axis is renormalised away. That
# is the behaviour worth measuring on it, not a gap in the fixture.
case "$PKG" in
  apt|dnf) INIT=systemd ;;
  apk) INIT=openrc ;;
esac

pkg_install() {
  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
    dnf) dnf install -y -q "$@" >/dev/null 2>&1 ;;
    apk) apk add --quiet --no-cache "$@" >/dev/null 2>&1 ;;
  esac
}

pkg_refresh() {
  case "$PKG" in
    apt) apt-get update -qq >/dev/null 2>&1 ;;
    dnf) dnf makecache -q >/dev/null 2>&1 ;;
    apk) apk update --quiet >/dev/null 2>&1 ;;
  esac
}

svc_enable() {
  case "$INIT" in
    systemd) systemctl enable --now "$1" >/dev/null 2>&1 ;;
    openrc) rc-update add "$1" default >/dev/null 2>&1; rc-service "$1" start >/dev/null 2>&1 ;;
  esac
}

svc_disable() {
  case "$INIT" in
    systemd) systemctl disable --now "$1" >/dev/null 2>&1 ;;
    openrc) rc-service "$1" stop >/dev/null 2>&1; rc-update del "$1" default >/dev/null 2>&1 ;;
  esac
}

svc_restart() {
  case "$INIT" in
    systemd) systemctl restart "$1" >/dev/null 2>&1 ;;
    openrc) rc-service "$1" restart >/dev/null 2>&1 ;;
  esac
}

# The names differ, and picking the wrong one fails silently: the service
# simply never starts and the finding it was meant to produce never fires.
case "$PKG" in
  apt) SSHD_SVC=ssh; SSHD_PKG=openssh-server; REDIS_PKG=redis-server; REDIS_SVC=redis-server; REDIS_CONF=/etc/redis/redis.conf ;;
  dnf) SSHD_SVC=sshd; SSHD_PKG=openssh-server; REDIS_PKG=redis; REDIS_SVC=redis; REDIS_CONF=/etc/redis/redis.conf ;;
  apk) SSHD_SVC=sshd; SSHD_PKG=openssh; REDIS_PKG=redis; REDIS_SVC=redis; REDIS_CONF=/etc/redis.conf ;;
esac

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

SEED_HOME=$(getent passwd "$SEED_USER" 2>/dev/null | cut -d: -f6)
# busybox getent is absent on a minimal Alpine; the passwd file is the same
# file hostveil's own agent checker reads, so fall back to it rather than to a
# guess at /root.
[ -n "$SEED_HOME" ] || SEED_HOME=$(awk -F: -v u="$SEED_USER" '$1 == u { print $6 }' /etc/passwd)
[ -n "$SEED_HOME" ] || { echo "seed: no such user: $SEED_USER" >&2; exit 1; }

say "base packages ($DISTRO_ID, $PKG, $INIT)"
pkg_refresh
# ufw is Debian's; Fedora ships firewalld and Alpine neither. hostveil probes
# ufw, firewall-cmd, nft and iptables in that order, so what matters is that
# *a* firewall exists to be found switched off — not which one.
case "$PKG" in
  apt) pkg_install ca-certificates curl git ufw "$SSHD_PKG" sudo iproute2 systemd-sysv python3 jq || true ;;
  dnf) pkg_install ca-certificates curl git firewalld "$SSHD_PKG" sudo iproute python3 jq || true ;;
  apk) pkg_install ca-certificates curl git iptables "$SSHD_PKG" sudo iproute2 python3 jq openrc bash || true ;;
esac

say "docker"
if ! command -v docker >/dev/null 2>&1; then
  # get.docker.com does not support Alpine; its own package does.
  if [ "$PKG" = apk ]; then
    pkg_install docker docker-cli-compose || true
  else
    curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 || true
  fi
fi
svc_enable docker || true
docker version --format '{{.Server.Version}}' 2>&1 | tail -1
# Half the domains are about containers, so a host without a daemon is not a
# different measurement, it is most of one missing.
require docker have_docker

say "weak SSH — a drop-in that outranks the image's own"
# Ubuntu's sshd_config includes sshd_config.d/*.conf at the top and sshd keeps
# the FIRST value it obtains for each keyword, so the cloud image's own
# drop-ins beat anything appended to the main file. The 00- prefix sorts ahead
# of them. This also makes the fixture exercise the checker's Include handling
# rather than only its main-file parsing.
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$DEMO/seed/sshd_hostveil.conf" /etc/ssh/sshd_config.d/00-hostveil-demo.conf
# Not every sshd_config includes the drop-in directory. Ubuntu's does at the
# top of the file, which is what makes the 00- prefix win; Alpine's and
# Fedora's may not, and a drop-in nothing reads seeds nothing. Append the
# Include when it is absent rather than assuming the distribution's default.
if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
  printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> /etc/ssh/sshd_config
fi
svc_enable "$SSHD_SVC" || true
svc_restart "$SSHD_SVC" || true
require weak-ssh have_weak_ssh

say "firewall installed and left off, automatic updates installed and switched off"
case "$PKG" in
  apt) ufw --force disable >/dev/null 2>&1 || true; require firewall-off have_firewall ufw ;;
  dnf) svc_disable firewalld || true; require firewall-off have_firewall firewall-cmd ;;
  # Alpine has no ufw and no firewalld. iptables with an empty ruleset is the
  # honest equivalent: a firewall mechanism present and not filtering anything,
  # which is the state firewall.inactive describes.
  apk) require firewall-off have_firewall iptables ;;
esac

# unattended-upgrades is *installed* and then switched off, because that is
# what an ordinary Ubuntu box looks like: the package ships with the
# distribution and the operator turns it off, or a minimal image leaves the
# periodic keys at zero.
#
# The distinction decides which remediation hostveil offers, so seeding it
# wrong measures the wrong path. Writing the config for a package that is not
# installed — which this script used to do — produces a host no distribution
# ships: the finding then carries no config path, hostveil offers the exec
# install instead of the one-file edit, and apt's postinst leaves an existing
# "0" alone, so the fix completes and the finding survives. The harness caught
# it, as an apt config file changing with no before-state recorded for it.
case "$PKG" in
  apt)
    pkg_install unattended-upgrades || true
    svc_disable unattended-upgrades || true
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
    seeded updates-off
    ;;
  dnf)
    # Fedora's equivalent is dnf-automatic, installed and left disabled for the
    # same reason: it is what an ordinary host looks like when the operator
    # turned it off, and it is the state that decides which remediation
    # hostveil offers.
    pkg_install dnf-automatic || true
    svc_disable dnf-automatic.timer || true
    if command -v dnf-automatic >/dev/null 2>&1 || [ -f /etc/dnf/automatic.conf ]; then
      seeded updates-off
    else
      unseedable updates-off "dnf-automatic did not install"
    fi
    ;;
  apk)
    # Alpine ships no unattended-upgrade mechanism at all, so there is nothing
    # to install and switch off. The domain has no weakness to find here, and
    # that raises the score for a reason that is about Alpine and not about
    # hostveil — which is why it is recorded rather than inferred.
    unseedable updates-off "Alpine ships no unattended-upgrade mechanism"
    ;;
esac

say "host-level weaknesses — a native datastore on 0.0.0.0, a uid-0 twin, loose perms"
# A NON-Docker datastore on every interface. This is the exposure a Compose
# audit can never see, and the one hostveil reports and declines to fix,
# because the config path differs per datastore.
pkg_install "$REDIS_PKG" || true
if [ -f "$REDIS_CONF" ]; then
  sed -i 's/^bind .*/bind 0.0.0.0/; s/^protected-mode yes/protected-mode no/' "$REDIS_CONF" 2>/dev/null || true
  # apt's postinst already starts the service before this edit runs, and
  # `enable --now` on an already-running unit does not reload its config —
  # it has to be a restart, or the listener stays on the package's default
  # bind address and the weakness silently fails to seed.
  svc_enable "$REDIS_SVC" || true
  svc_restart "$REDIS_SVC" \
    || redis-server "$REDIS_CONF" --daemonize yes >/dev/null 2>&1 || true
fi
# The listener is the weakness, not the package. This is the exposure a Compose
# audit can never see, and it is the one hostveil reports and declines to fix
# because the config path differs per datastore — so a run without it is
# missing the finding that argues for that decline.
if have_exposed_redis; then
  seeded exposed-datastore
else
  unseedable exposed-datastore "redis did not come up listening on 0.0.0.0:6379"
fi

# adduser on Alpine is busybox's and takes different flags from shadow's
# useradd, which is not installed there by default.
if [ "$PKG" = apk ]; then
  pkg_install shadow >/dev/null 2>&1 || true
fi
id breakglass >/dev/null 2>&1 || useradd -o -u 0 -g 0 -M -s /bin/bash breakglass
id contractor >/dev/null 2>&1 || useradd -m -s /bin/bash contractor
passwd -d contractor >/dev/null 2>&1 || true
chmod 0644 /etc/shadow
require uid0-twin have_uid0_twin
require shadow-readable have_open_shadow

say "sysctl overrides that fight the distribution's own defaults"
# ptrace_scope=0 and perf_event_paranoid<2 are among the most-copied lines in
# "gdb: Operation not permitted" and "perf: Permission denied" troubleshooting
# guides — an operator running a game server or profiling a stuck daemon
# applies both and drops them in sysctl.d to survive a reboot. This is an
# operator undoing a hardened default, not merely leaving one alone; most of
# the sysctl domain's other rules already match what these distributions ship
# and would need a far less plausible edit to trip.
cat > /etc/sysctl.d/98-local.conf <<'EOF'
kernel.yama.ptrace_scope = 0
kernel.perf_event_paranoid = -1
EOF
sysctl -p /etc/sysctl.d/98-local.conf >/dev/null 2>&1 || true
require debug-sysctl have_debug_sysctl

say "an unhardened operator-written systemd unit"
case "$INIT" in
  systemd)
    # A hand-written backup unit with none of the sandboxing directives — what
    # copying a tutorial's minimal [Unit]/[Service]/[Install] skeleton for a
    # backup script produces, and one of the most common ways a self-hoster
    # ends up with an *operator* unit (as opposed to a distro-packaged one) in
    # the first place.
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
    systemctl daemon-reload
    systemctl start stacks-backup.service || true
    require systemd-unhardened-unit have_unhardened_unit
    ;;
  openrc)
    unseedable systemd-unhardened-unit "Alpine runs OpenRC — no systemd units to leave unhardened"
    ;;
esac

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
# These paths are the ones internal/docs/seed_test.go holds against the agent
# checker's own table, which is what stopped an earlier copy of this script
# writing them somewhere the scan never looks.
require agent-configs have_agent_cfg

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
# The compose *files* are what the container domain audits, so they are the
# weakness — a service that failed to start still produces its findings.
require compose-stacks have_stacks

if [ "$INSTRUMENTS" = 1 ]; then
  say "the instruments the harness reports through"
  # Absent ones are recorded as absent rather than passed over, so this is a
  # convenience — but a run missing one is a run missing a whole column, and
  # the CVE domain being absent also *raises* the score, because an excluded
  # axis leaves the denominator rather than scoring zero.
  pkg_install lynis || echo "  lynis: install failed (no packaged lynis on $DISTRO_ID)"
  if [ ! -x /opt/docker-bench-security/docker-bench-security.sh ]; then
    if git init -q /opt/docker-bench-security &&
      git -C /opt/docker-bench-security remote add origin https://github.com/docker/docker-bench-security.git &&
      git -C /opt/docker-bench-security fetch -q --depth 1 origin "$DOCKER_BENCH_REV" &&
      git -C /opt/docker-bench-security checkout -q --detach FETCH_HEAD; then
      :
    else
      echo "  docker-bench: pinned checkout failed"
    fi
  fi
  chmod +x /opt/docker-bench-security/docker-bench-security.sh 2>/dev/null || true
  if ! command -v trivy >/dev/null 2>&1; then
    curl -sfL "https://raw.githubusercontent.com/aquasecurity/trivy/$TRIVY_INSTALL_REV/contrib/install.sh" \
      | sh -s -- -b /usr/local/bin >/dev/null 2>&1 || echo "  trivy: install failed"
  fi
  trivy image --download-db-only >/dev/null 2>&1 || true
fi

write_manifest

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
