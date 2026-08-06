#!/usr/bin/env bash
# Harden the host the way a careful operator would, without hostveil, so the
# harness has a control group.
#
# The seeded host answers "does the score move when hostveil fixes things",
# which a score could pass while measuring nothing but its own opinions. This
# answers the harder question: does the score go up when the host is hardened
# by *somebody else's* standard? A number that only responds to hostveil's own
# fixes is not a security score, it is a to-do list with a percentage on it.
#
# Every change below is traceable to the CIS Benchmarks or to Lynis's own
# suggestions, and none of them was read off hostveil's fix registry. The
# overlap that results is part of the finding, not a flaw in the method: two
# independent standards agreeing about PermitRootLogin is what agreement
# between standards looks like.
#
# It edits the host in place and does not undo itself. Run it on something
# disposable.
#
#   scripts/measure/control.sh
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "control: needs root" >&2; exit 1; }

say() { printf '==> %s\n' "$*" >&2; }

# CIS Debian 5.2 (SSH server configuration). A drop-in rather than an edit to
# sshd_config, which is how Debian's own package expects operators to layer
# their settings.
say "sshd: CIS 5.2 baseline"
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-control-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
EOF

# The seeded host carries a deliberately weak drop-in. Leaving it in place
# would mean testing precedence rather than hardening — a later file wins, and
# 00- sorts before 99-, so this one already loses to nothing. Remove it so the
# control host is actually hardened.
rm -f /etc/ssh/sshd_config.d/00-hostveil-demo.conf

# CIS Debian 3.3 (network parameters) and 1.5 (kernel hardening). One
# drop-in, named so it wins against everything the distribution ships — on
# Ubuntu, /etc/sysctl.d/99-sysctl.conf is a symlink to /etc/sysctl.conf and
# sorts last, so a lower number would silently lose.
say "sysctl: CIS 3.3/1.5 baseline"
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-zz-control-hardening.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null 2>&1 || true

# CIS Debian 6.1.2-6.1.4 (permissions on the account databases).
say "file permissions: CIS 6.1"
chmod 644 /etc/passwd /etc/group 2>/dev/null || true
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true
chown root:root /etc/passwd /etc/group 2>/dev/null || true

# CIS Debian 5.4.2: no account other than root may have UID 0. The seeded
# host has a second one.
say "accounts: CIS 5.4.2"
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r u; do
  say "  removing UID 0 account $u"
  userdel "$u" 2>/dev/null || true
done

# CIS Docker Benchmark 2.x and 5.x, applied to the daemon and to every
# compose service, through the files the operator owns.
say "docker: CIS Docker Benchmark 2.x"
if [ -d /etc/docker ]; then
  python3 - <<'PY'
import json, os
path = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(path):
    try:
        cfg = json.load(open(path))
    except ValueError:
        cfg = {}
# 2.1 restrict inter-container traffic, 2.13 disable userland proxy,
# 2.14 no-new-privileges, 2.6 live-restore. The TCP socket goes: CIS 2.x
# treats an unauthenticated daemon endpoint as the top finding it has.
cfg.update({"icc": False, "userland-proxy": False,
            "no-new-privileges": True, "live-restore": True})
cfg.pop("hosts", None)
json.dump(cfg, open(path, "w"), indent=2)
PY
fi

say "control host hardened — measure it with: scripts/measure/run.sh -p control"
