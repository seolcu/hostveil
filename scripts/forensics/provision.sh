#!/usr/bin/env bash
# Base testbed: a distribution-default Ubuntu web server. Nothing here is
# hardened or weakened on purpose; the point is to measure what a stock
# install records.
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
# The host this was built on reached the internet through a proxy recorded
# in /etc/environment; a provisioner shell does not read it on its own.
# shellcheck disable=SC1091 # read at runtime from the host being provisioned
if [[ -f /etc/environment ]]; then set -a; . /etc/environment; set +a; fi

apt-get update -q
apt-get install -y -q apache2 libapache2-mod-php php-cli curl rsyslog jq \
  rkhunter chkrootkit lynis >/dev/null

# A tiny "application": a page, an export area a script can bulk-download,
# and an upload directory, as most PHP apps have.
mkdir -p /var/www/html/uploads /var/www/html/export
echo '<?php echo "hello"; ?>' > /var/www/html/index.php
for i in $(seq 1 30); do echo "<h1>book $i</h1>" > "/var/www/html/export/book$i.html"; done
chown -R www-data:www-data /var/www/html

# A second login account, as on a shared server.
id alice >/dev/null 2>&1 || useradd -m -s /bin/bash alice

# UAC, the live-response collector the comparison uses (release tarball,
# pinned and checksummed).
UAC_VER=3.4.0
UAC_SHA256=d333b72990c25d48b93200648a58084f8b79ff917d1e609dd92ac6ba9fb387db
if [[ ! -d /opt/uac ]]; then
  curl -fsSL -o /tmp/uac.tar.gz "https://github.com/tclahr/uac/releases/download/v${UAC_VER}/uac-${UAC_VER}.tar.gz"
  echo "${UAC_SHA256}  /tmp/uac.tar.gz" | sha256sum -c --quiet
  mkdir -p /opt/uac && tar -xzf /tmp/uac.tar.gz -C /opt/uac --strip-components=1
fi

systemctl enable --now apache2 >/dev/null
echo "provision_ok"
