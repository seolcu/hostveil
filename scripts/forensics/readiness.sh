#!/usr/bin/env bash
# Bring the testbed to the forensic-readiness state hostveil recommends:
# every forensic.* fix it offers, applied through hostveil itself, plus the
# Manual steps its how-to-fix text describes that one host can carry out
# (installing auditd, adding request size to the Apache log format). Remote
# logging needs a second machine and is left undone, so its gap remains.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
HV=/fx/.bin/hostveil
scan() { HOSTVEIL_NO_SUDO=1 "$HV" scan --json --only forensic; }

# Manual: auditd (forensic.auditd-missing).
apt-get install -y -q auditd >/dev/null
systemctl enable --now auditd >/dev/null

# Manual: request size and time in the Apache access log (forensic.weblog-no-size).
a2enmod -q logio >/dev/null
cat > /etc/apache2/conf-available/forensic-log.conf <<'CONF'
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %I %D" forensic
CONF
a2enconf -q forensic-log >/dev/null
sed -i 's/CustomLog ${APACHE_LOG_DIR}\/access.log combined/CustomLog ${APACHE_LOG_DIR}\/access.log forensic/' /etc/apache2/sites-enabled/000-default.conf
systemctl reload apache2

# Every fix hostveil offers in the domain, first alternative.
scan > /root/readiness-before.json || true
jq -r '.findings[] | select(.source == "forensic" or (.id | startswith("forensic."))) | select(.remediation != "manual") | [.id, .service] | @tsv' /root/readiness-before.json |
while IFS=$'\t' read -r id svc; do
  args=(fix "$id" --yes)
  [[ -n $svc ]] && args+=(--service "$svc")
  echo "applying $id ${svc:+($svc)}"
  HOSTVEIL_NO_SUDO=1 "$HV" "${args[@]}" || echo "fix_failed $id"
done
scan > /root/readiness-after.json || true
echo "readiness_done"
