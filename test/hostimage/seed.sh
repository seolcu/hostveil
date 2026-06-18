#!/bin/sh
# seed.sh — runs inside the hostveil test-host container.
# Brings up sshd, fail2ban, and nginx so the scanners have
# something to find. Writes the per-finding assertion markers
# to a known location the integration test can read.

set -e

# Bring up sshd in the background. We don't use systemd in the
# container; we just start the daemon.
mkdir -p /run/sshd
/usr/sbin/sshd -D -e 2>/tmp/sshd.log &

# Bring up nginx.
nginx 2>/tmp/nginx.log &

# Bring up fail2ban.
mkdir -p /var/run/fail2ban
fail2ban-client -x start 2>/tmp/fail2ban.log || true

# Run the hostveil scan on this host, writing the report to
# /tmp/hostveil-report.txt. The integration test then reads
# this file.
if command -v /usr/local/bin/hostveil >/dev/null 2>&1; then
  /usr/local/bin/hostveil scan --report-dir /tmp >/dev/null 2>&1 || true
fi

# Keep the container alive for the integration test to exec into.
exec tail -f /dev/null
