#!/usr/bin/env bash
# Apply hostveil's individual-only fixes on a real host and check each one:
# the seeded finding is reported, the fix lands, the host really changed, a
# rescan agrees, and a rollback puts the host back.
#
# Usage (as root, on a disposable host — it edits /etc and restarts daemons):
#   scripts/e2e/individual.sh accounts       # no daemons needed; container-safe
#   scripts/e2e/individual.sh owner          # no daemons needed; container-safe
#   scripts/e2e/individual.sh compose        # needs a Docker daemon
#   scripts/e2e/individual.sh dockerd        # needs Docker under systemd
#   scripts/e2e/individual.sh dockerd-revert # needs Docker under systemd
#   scripts/e2e/individual.sh systemd        # needs systemd as PID 1
#   scripts/e2e/individual.sh nginx          # installs nginx; needs systemd
#   scripts/e2e/individual.sh reboot-preview # never reboots
#   scripts/e2e/individual.sh ufw            # enables ufw; needs Docker and sshd
#   scripts/e2e/individual.sh k3s            # installs k3s
#   scripts/e2e/individual.sh caddy          # installs Caddy; needs systemd
#   scripts/e2e/individual.sh traefik        # needs a Docker daemon
#   scripts/e2e/individual.sh openclaw       # installs OpenClaw from npm
#   scripts/e2e/individual.sh proxmox        # Debian 12 or 13; fakes /etc/pve, uses the real repositories
#
# Why it exists: these fixes are excluded from every batch on purpose, so
# `fix --all --review` — the E2E job's and the measurement harness's path —
# never runs them. Before this, every one of them had been exercised against a
# fake CommandRunner and nothing else.

set -euo pipefail

export HOSTVEIL_NO_SUDO=1
HV=${HOSTVEIL:-hostveil}

# DIAGNOSE names a unit whose state is worth printing when a scenario fails;
# a daemon left down says why in its own journal, not in ours.
DIAGNOSE=""

fail() {
    printf 'FAIL %s\n' "$*" >&2
    if [[ -n $DIAGNOSE ]] && command -v systemctl >/dev/null; then
        systemctl status "$DIAGNOSE" --no-pager -l 2>&1 | tail -15 >&2 || true
        journalctl -u "$DIAGNOSE" -n 30 --no-pager 2>&1 >&2 || true
    fi
    exit 1
}

step() { printf '\n== %s\n' "$*"; }

# count ID [SERVICE]: how many open findings with this ID (and service) the
# scan reports. scan exits non-zero when it finds High findings, which on a
# seeded host is the point, so its status is not the test.
count() {
    local id=$1 svc=${2:-}
    "$HV" scan --json 2>/dev/null >/tmp/hv-scan.json || true
    jq --arg id "$id" --arg svc "$svc" \
        '[.findings[] | select(.id == $id and ($svc == "" or .service == $svc))] | length' /tmp/hv-scan.json
}

expect_count() {
    local want=$1 id=$2 svc=${3:-} got
    got=$(count "$id" "$svc")
    [[ $got == "$want" ]] || fail "$id${svc:+ ($svc)}: scan reports $got, want $want"
}

# apply ID [SERVICE] [ACTION]
apply() {
    local id=$1 svc=${2:-} action=${3:-0}
    local args=("$id" --action "$action" --yes)
    [[ -n $svc ]] && args+=(--service "$svc")
    "$HV" fix "${args[@]}" || fail "hostveil fix ${args[*]} failed"
}

# rollback_latest ID: undo the newest checkpoint for a finding. history lists
# newest first, one line per checkpoint naming the finding and, when it can be
# undone, the rollback command.
rollback_latest() {
    local id=$1 cp
    cp=$("$HV" history | grep -F "  $id  (" | grep -m1 -o 'hostveil rollback [^] ]*' | awk '{print $3}') ||
        fail "$id: no checkpoint in history to roll back"
    "$HV" rollback "$cp" || fail "rollback $cp failed"
}

# --- accounts ----------------------------------------------------------------

scenario_accounts() {
    step "accounts.uid0: lock and expire a second root"
    id backdoor >/dev/null 2>&1 || useradd -o -u 0 -g 0 -M -s /bin/bash backdoor
    echo 'backdoor:hunter2' | chpasswd
    expect_count 1 accounts.uid0
    apply accounts.uid0
    grep -E '^backdoor:!' /etc/shadow >/dev/null || fail "backdoor's password is not locked"
    [[ $(getent shadow backdoor | cut -d: -f8) == 1 ]] || fail "backdoor's expiry is not day 1"
    expect_count 0 accounts.uid0
    userdel backdoor 2>/dev/null || true

    step "accounts.weak-password-hash: expire an MD5 password"
    id weakhash >/dev/null 2>&1 || useradd -m -s /bin/bash weakhash
    usermod -p "$(openssl passwd -1 hunter2)" weakhash
    expect_count 1 accounts.weak-password-hash
    apply accounts.weak-password-hash
    chage -l weakhash | grep -qi 'password must be changed' || fail "weakhash's password was not expired"
    # The hash only changes at the next password change, so the finding
    # stays; TakesEffectOn says so. Reporting it gone would be the lie.
    expect_count 1 accounts.weak-password-hash
    userdel -r weakhash 2>/dev/null || true
}

# --- ownership ---------------------------------------------------------------

scenario_owner() {
    step "fileperms.owner: give /etc/shadow back to root, then roll back"
    id e2eowner >/dev/null 2>&1 || useradd -M -u 1500 e2eowner
    local group_before
    group_before=$(stat -c %g /etc/shadow)
    chown 1500 /etc/shadow
    expect_count 1 fileperms.owner
    apply fileperms.owner
    [[ $(stat -c %u /etc/shadow) == 0 ]] || fail "/etc/shadow is not owned by root after the fix"
    [[ $(stat -c %g /etc/shadow) == "$group_before" ]] || fail "the fix changed /etc/shadow's group"
    expect_count 0 fileperms.owner
    rollback_latest fileperms.owner
    [[ $(stat -c %u /etc/shadow) == 1500 ]] || fail "rollback did not restore /etc/shadow's owner"
    chown 0 /etc/shadow
    userdel e2eowner 2>/dev/null || true
}

# --- compose -----------------------------------------------------------------

COMPOSE_DIR=/srv/hostveil-e2e

seed_compose() {
    mkdir -p "$COMPOSE_DIR"
    cat >"$COMPOSE_DIR/compose.yaml" <<'YAML'
services:
  risky:
    image: busybox:1.36
    command: ["sleep", "infinity"]
    restart: unless-stopped
    mem_limit: 64m
    security_opt:
      - no-new-privileges:true
    privileged: true
    cap_add:
      - SYS_ADMIN
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host/etc
YAML
    docker compose -f "$COMPOSE_DIR/compose.yaml" up -d --quiet-pull
}

scenario_compose() {
    seed_compose
    for id in compose.ds001 compose.ds005 compose.ds016 compose.ds017 compose.ds022; do
        step "$id"
        local before
        before=$(sha256sum "$COMPOSE_DIR/compose.yaml" | cut -d' ' -f1)
        [[ $(count "$id") -ge 1 ]] || fail "$id is not reported on the seeded project"
        apply "$id" "$(jq -r --arg id "$id" '[.findings[] | select(.id == $id)][0].service' /tmp/hv-scan.json)"
        docker compose -f "$COMPOSE_DIR/compose.yaml" config -q || fail "$id left a compose file docker rejects"
        docker compose -f "$COMPOSE_DIR/compose.yaml" up -d --quiet-pull || fail "$id left a service that will not start"
        expect_count 0 "$id"
        rollback_latest "$id"
        [[ $(sha256sum "$COMPOSE_DIR/compose.yaml" | cut -d' ' -f1) == "$before" ]] ||
            fail "$id: rollback did not restore compose.yaml byte for byte"
    done
    docker compose -f "$COMPOSE_DIR/compose.yaml" down -t 1 >/dev/null 2>&1 || true
}

# --- dockerd -----------------------------------------------------------------

DAEMON_JSON=/etc/docker/daemon.json

scenario_dockerd() {
    DIAGNOSE=docker
    step "dockerd.live-restore: set and reload"
    local before=""
    [[ -f $DAEMON_JSON ]] && before=$(cat "$DAEMON_JSON")
    expect_count 1 dockerd.live-restore
    apply dockerd.live-restore
    [[ $(docker info --format '{{.LiveRestoreEnabled}}') == true ]] || fail "docker info does not report live-restore after the fix"
    expect_count 0 dockerd.live-restore
    rollback_latest dockerd.live-restore
    [[ $(docker info --format '{{.LiveRestoreEnabled}}') == false ]] || fail "live-restore still on after rollback"

    step "dockerd.no-new-privileges: set and restart Docker"
    expect_count 1 dockerd.no-new-privileges
    apply dockerd.no-new-privileges
    docker info --format '{{.SecurityOptions}}' | grep -q no-new-privileges || fail "docker info does not report no-new-privileges"
    expect_count 0 dockerd.no-new-privileges
    rollback_latest dockerd.no-new-privileges
    docker info >/dev/null || fail "Docker does not answer after rolling back"
    if [[ -n $before ]]; then
        [[ $(cat "$DAEMON_JSON") == "$before" ]] || fail "daemon.json is not back to what it was"
    elif [[ -f $DAEMON_JSON ]]; then
        fail "daemon.json did not exist before the fixes and still exists after rolling them back"
    fi
}

# The promise #829 made: a daemon that refuses the new file is given the old
# one back and started again. Seed a daemon.json Docker accepts and a flag on
# the unit that collides with the key the fix adds, so the restart fails for a
# reason that is about the edit.
scenario_dockerd_revert() {
    DIAGNOSE=docker
    step "dockerd: a restart that fails puts the original daemon.json back"
    mkdir -p /etc/systemd/system/docker.service.d
    printf '[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock --no-new-privileges=false\n' \
        >/etc/systemd/system/docker.service.d/50-e2e-conflict.conf
    # The scenario before this one restarted Docker several times inside a
    # minute, which is docker.service's start limit; clear it so the seed's
    # own restarts are not what fails.
    systemctl daemon-reload
    systemctl reset-failed docker
    systemctl restart docker
    printf '{\n  "log-level": "info"\n}\n' >"$DAEMON_JSON"
    systemctl reset-failed docker
    systemctl restart docker
    local before
    before=$(sha256sum "$DAEMON_JSON" | cut -d' ' -f1)
    expect_count 1 dockerd.no-new-privileges
    # Compared before and after rather than required to be zero: an earlier
    # scenario on the same host leaves its own, rolled-back checkpoints.
    local recorded
    recorded=$("$HV" history | grep -cF '  dockerd.no-new-privileges  (' || true)
    if "$HV" fix dockerd.no-new-privileges --action 0 --yes >/tmp/hv-revert.log 2>&1; then
        cat /tmp/hv-revert.log
        fail "the fix reported success with a key Docker refuses alongside the same flag"
    fi
    cat /tmp/hv-revert.log
    [[ $(sha256sum "$DAEMON_JSON" | cut -d' ' -f1) == "$before" ]] || fail "daemon.json was not restored"
    docker info >/dev/null || fail "Docker is down after the failed fix"
    [[ $("$HV" history | grep -cF '  dockerd.no-new-privileges  (' || true) == "$recorded" ]] ||
        fail "history gained a checkpoint for a change that was undone"
    rm -f /etc/systemd/system/docker.service.d/50-e2e-conflict.conf
    systemctl daemon-reload
    systemctl reset-failed docker
    systemctl restart docker
}

# --- systemd -----------------------------------------------------------------

scenario_systemd() {
    cat >/etc/systemd/system/hostveil-e2e.service <<'UNIT'
[Unit]
Description=hostveil e2e target

[Service]
ExecStart=/bin/sleep infinity

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl start hostveil-e2e.service
    for pair in systemd.private-tmp:PrivateTmp systemd.protect-home:ProtectHome; do
        local id=${pair%%:*} prop=${pair##*:}
        step "$id"
        expect_count 1 "$id" hostveil-e2e.service
        apply "$id" hostveil-e2e.service
        systemctl daemon-reload
        local v
        v=$(systemctl show hostveil-e2e.service -p "$prop" --value)
        [[ $v == yes || $v == true ]] || fail "$id: systemctl show reports $prop=$v after the drop-in"
        expect_count 0 "$id" hostveil-e2e.service
        rollback_latest "$id"
        systemctl daemon-reload
        [[ $(count "$id" hostveil-e2e.service) == 1 ]] || fail "$id: rollback did not bring the finding back"
    done
    systemctl stop hostveil-e2e.service
    rm -f /etc/systemd/system/hostveil-e2e.service
    systemctl daemon-reload
}

# --- nginx -------------------------------------------------------------------

scenario_nginx() {
    if ! command -v nginx >/dev/null; then
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null
    fi
    local site=/etc/nginx/conf.d/hostveil-e2e.conf
    # One file carries both directives, so each finding names exactly one file.
    sed -i 's/^\(\s*ssl_protocols\)/#\1/' /etc/nginx/nginx.conf
    cat >"$site" <<'NGINX'
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
server {
    listen 127.0.0.1:8099;
    location /files/ {
        root /srv;
        autoindex on;
    }
}
NGINX
    DIAGNOSE=nginx
    nginx -t
    # Running, so the fixes' reload is the path under test; an installed but
    # stopped nginx is left stopped by them, which is a different case.
    systemctl restart nginx
    local before
    before=$(sha256sum "$site" | cut -d' ' -f1)
    for id in proxy.tls-deprecated-protocols proxy.directory-listing; do
        step "$id"
        expect_count 1 "$id"
        apply "$id"
        systemctl is-active --quiet nginx || fail "$id left nginx down"
        expect_count 0 "$id"
    done
    nginx -T 2>/dev/null | grep -q 'ssl_protocols TLSv1.2 TLSv1.3;' || fail "nginx is not serving the new ssl_protocols"
    nginx -T 2>/dev/null | grep -q 'autoindex off;' || fail "nginx is not serving autoindex off"
    rollback_latest proxy.directory-listing
    rollback_latest proxy.tls-deprecated-protocols
    [[ $(sha256sum "$site" | cut -d' ' -f1) == "$before" ]] || fail "rollback did not restore $site byte for byte"
    systemctl is-active --quiet nginx || fail "nginx is down after rolling back"
    rm -f "$site"
    systemctl reload nginx
}

# --- ufw -----------------------------------------------------------------------

# A listener the ports checker reads as a datastore: anything on 6379 is
# Redis to it, and a plain HTTP server is the cheapest thing that listens.
start_listener() {
    python3 -m http.server 6379 --bind 0.0.0.0 >/dev/null 2>&1 &
    LISTENER=$!
    for _ in $(seq 1 20); do
        ss -ltn | grep -q ':6379 ' && return 0
        sleep 0.5
    done
    fail "the test listener on 6379 did not come up"
}

scenario_ufw() {
    DIAGNOSE=ufw
    command -v ufw >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null; }
    # The firewall fix allows the port sshd is listening on before it denies
    # the rest, so there has to be an sshd for it to find.
    if ! ss -ltnp | grep -q sshd; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null
        systemctl start ssh
    fi
    ufw --force reset >/dev/null

    step "firewall.inactive: enable ufw, allowing SSH first"
    expect_count 1 firewall.inactive
    apply firewall.inactive
    ufw status | grep -q 'Status: active' || fail "ufw is not active after the fix"
    ufw status | grep -qE '^22/tcp +ALLOW' || fail "the SSH port was not allowed before the policy changed"
    expect_count 0 firewall.inactive

    step "ports.exposed-datastore: close an allowed port ahead of the allow"
    ufw allow 6379/tcp >/dev/null
    start_listener
    local svc
    [[ $(count ports.exposed-datastore) -ge 1 ]] || fail "ports.exposed-datastore is not reported on an allowed 6379"
    svc=$(jq -r '[.findings[] | select(.id == "ports.exposed-datastore")][0].service' /tmp/hv-scan.json)
    apply ports.exposed-datastore "$svc"
    ufw status | awk '/6379\/tcp/ {print $2; exit}' | grep -q DENY || fail "the deny for 6379 is not ahead of the allow"
    expect_count 0 ports.exposed-datastore
    kill "$LISTENER" 2>/dev/null || true
    ufw delete deny 6379/tcp >/dev/null || true
    ufw delete allow 6379/tcp >/dev/null || true

    step "firewall.docker-bypass: the ufw-docker rules, then roll them back"
    docker rm -f hv-web >/dev/null 2>&1 || true
    docker run -d --name hv-web -p 8088:80 busybox:1.36 httpd -f -p 80 >/dev/null
    local before
    before=$(sha256sum /etc/ufw/after.rules | cut -d' ' -f1)
    expect_count 1 firewall.docker-bypass
    apply firewall.docker-bypass
    iptables -S DOCKER-USER | grep -q ufw-user-forward || fail "DOCKER-USER does not send traffic through ufw after the fix"
    expect_count 0 firewall.docker-bypass
    rollback_latest firewall.docker-bypass
    [[ $(sha256sum /etc/ufw/after.rules | cut -d' ' -f1) == "$before" ]] || fail "after.rules is not back byte for byte"
    if iptables -S DOCKER-USER | grep -q ufw-user-forward; then
        fail "the rollback restored after.rules but DOCKER-USER still sends traffic through ufw"
    fi
    expect_count 1 firewall.docker-bypass

    docker rm -f hv-web >/dev/null 2>&1 || true
    ufw --force reset >/dev/null
}

# --- k3s -----------------------------------------------------------------------

k3s_ready() {
    for _ in $(seq 1 90); do
        k3s kubectl get --raw /readyz >/dev/null 2>&1 && return 0
        sleep 2
    done
    fail "k3s did not become ready"
}

# The status an unauthenticated request for /version gets: 200 while anonymous
# requests are let through to RBAC, 401 once they are refused.
anonymous_status() {
    curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:6443/version
}

scenario_k3s() {
    DIAGNOSE=k3s
    mkdir -p /etc/rancher/k3s
    printf 'kube-apiserver-arg:\n  - anonymous-auth=true\n' >/etc/rancher/k3s/config.yaml
    if ! command -v k3s >/dev/null; then
        curl -sfL https://get.k3s.io |
            INSTALL_K3S_EXEC="server --disable traefik --disable metrics-server" sh - >/dev/null
    fi
    k3s_ready

    step "kube.anonymous-auth: refuse unauthenticated requests, then roll back"
    [[ $(anonymous_status) == 200 ]] || fail "the seeded cluster does not let anonymous requests through ($(anonymous_status))"
    expect_count 1 kube.anonymous-auth
    apply kube.anonymous-auth
    k3s_ready
    [[ $(anonymous_status) == 401 ]] || fail "anonymous requests still get $(anonymous_status) after the fix"
    expect_count 0 kube.anonymous-auth
    rollback_latest kube.anonymous-auth
    k3s_ready
    [[ $(anonymous_status) == 200 ]] || fail "anonymous requests get $(anonymous_status) after rolling back"
    expect_count 1 kube.anonymous-auth

    # Not rolled back: once Secrets have been written encrypted, switching
    # encryption off by removing the setting leaves them unreadable, and the
    # fix's own Warning says not to. What is checked is that it is on.
    step "kube.secrets-unencrypted: encrypt Secrets at rest"
    # A Secret written before the fix, which the key rotation has to rewrite.
    k3s kubectl create secret generic hv-e2e --from-literal=password=hunter2 >/dev/null
    k3s secrets-encrypt status | grep -q 'Encryption Status: Disabled' || fail "the seeded cluster already encrypts Secrets"
    expect_count 1 kube.secrets-unencrypted
    apply kube.secrets-unencrypted
    k3s_ready
    if ! k3s secrets-encrypt status | grep -q 'Encryption Status: Enabled'; then
        k3s secrets-encrypt status >&2 || true
        fail "k3s does not report secrets encryption enabled"
    fi
    [[ $(k3s kubectl get secret hv-e2e -o jsonpath='{.data.password}' | base64 -d) == hunter2 ]] ||
        fail "the Secret written before the fix cannot be read after it"
    expect_count 0 kube.secrets-unencrypted
    "$HV" history | grep -F '  kube.secrets-unencrypted  (' | grep -q 'not reversible' ||
        fail "the encryption fix is listed as reversible"
}

# --- Caddy ---------------------------------------------------------------------

scenario_caddy() {
    DIAGNOSE=caddy
    command -v caddy >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy >/dev/null; }
    cat >/etc/caddy/Caddyfile <<'CADDY'
{
	admin 0.0.0.0:2019
}

:8090 {
	respond "ok"
}
CADDY
    systemctl restart caddy
    local ip before
    ip=$(hostname -I | awk '{print $1}')
    before=$(sha256sum /etc/caddy/Caddyfile | cut -d' ' -f1)
    sleep 1
    curl -sf "http://$ip:2019/config/" >/dev/null || fail "the seeded admin API does not answer on $ip"

    step "proxy.admin-api-exposed: move Caddy's admin API back to loopback"
    expect_count 1 proxy.admin-api-exposed
    apply proxy.admin-api-exposed
    sleep 1
    if curl -sf "http://$ip:2019/config/" >/dev/null; then
        fail "the admin API still answers on $ip after the fix"
    fi
    curl -sf http://127.0.0.1:2019/config/ >/dev/null || fail "the admin API does not answer on loopback after the fix"
    curl -sf http://127.0.0.1:8090/ | grep -q ok || fail "the site Caddy serves stopped answering"
    expect_count 0 proxy.admin-api-exposed

    rollback_latest proxy.admin-api-exposed
    sleep 1
    [[ $(sha256sum /etc/caddy/Caddyfile | cut -d' ' -f1) == "$before" ]] || fail "rollback did not restore the Caddyfile byte for byte"
    curl -sf "http://$ip:2019/config/" >/dev/null || fail "the admin API is not back on $ip after rolling back"
    expect_count 1 proxy.admin-api-exposed
}

# --- Traefik -------------------------------------------------------------------

TRAEFIK_DIR=/srv/hv-traefik

scenario_traefik() {
    mkdir -p "$TRAEFIK_DIR"
    cat >"$TRAEFIK_DIR/compose.yaml" <<'YAML'
services:
  traefik:
    image: traefik:v3.1
    command:
      - --api.insecure=true
      - --entrypoints.web.address=:80
    ports:
      - "127.0.0.1:8081:8080"
YAML
    docker compose -f "$TRAEFIK_DIR/compose.yaml" up -d --quiet-pull
    local before svc
    before=$(sha256sum "$TRAEFIK_DIR/compose.yaml" | cut -d' ' -f1)
    for _ in $(seq 1 30); do curl -sf http://127.0.0.1:8081/api/overview >/dev/null && break; sleep 1; done
    curl -sf http://127.0.0.1:8081/api/overview >/dev/null || fail "the seeded dashboard API does not answer"

    step "proxy.traefik-api-insecure: drop the flag and recreate Traefik"
    [[ $(count proxy.traefik-api-insecure) -ge 1 ]] || fail "proxy.traefik-api-insecure is not reported"
    svc=$(jq -r '[.findings[] | select(.id == "proxy.traefik-api-insecure")][0].service' /tmp/hv-scan.json)
    apply proxy.traefik-api-insecure "$svc" 0
    sleep 3
    if curl -sf http://127.0.0.1:8081/api/overview >/dev/null; then
        fail "the dashboard API still answers without authentication after the fix"
    fi
    expect_count 0 proxy.traefik-api-insecure

    rollback_latest proxy.traefik-api-insecure
    [[ $(sha256sum "$TRAEFIK_DIR/compose.yaml" | cut -d' ' -f1) == "$before" ]] || fail "rollback did not restore compose.yaml byte for byte"
    for _ in $(seq 1 30); do curl -sf http://127.0.0.1:8081/api/overview >/dev/null && break; sleep 1; done
    curl -sf http://127.0.0.1:8081/api/overview >/dev/null || fail "the rollback did not recreate Traefik with its dashboard"
    docker compose -f "$TRAEFIK_DIR/compose.yaml" down -t 1 >/dev/null 2>&1 || true
}

# --- OpenClaw ------------------------------------------------------------------

OC_USER=${SUDO_USER:-runner}

oc() { runuser -u "$OC_USER" -- openclaw "$@"; }

scenario_openclaw() {
    command -v openclaw >/dev/null || npm install -g --silent openclaw@latest >/dev/null 2>&1 || fail "npm could not install openclaw"
    local home cfg
    home=$(getent passwd "$OC_USER" | cut -d: -f6)
    cfg=$home/.openclaw/openclaw.json
    install -d -m 0700 -o "$OC_USER" "$home/.openclaw"
    cat >"$cfg" <<'JSON5'
{
  // seeded by hostveil's e2e; this comment must survive every edit
  "gateway": {"bind": "lan", "auth": {"mode": "none"}},
  "agents": {"defaults": {"sandbox": {"mode": "off"}}},
}
JSON5
    chown "$OC_USER" "$cfg"
    chmod 0600 "$cfg"
    [[ $(oc config get gateway.bind 2>/dev/null) == *lan* ]] || { oc config get gateway.bind || true; fail "OpenClaw does not read the seeded config"; }

    local svc
    step "agent.sandbox-off: turn the sandbox on, the way OpenClaw reads it"
    expect_count 1 agent.sandbox-off
    svc=$(jq -r '[.findings[] | select(.id == "agent.sandbox-off")][0].service' /tmp/hv-scan.json)
    apply agent.sandbox-off "$svc" 0
    [[ $(oc config get agents.defaults.sandbox.mode 2>/dev/null) == *non-main* ]] || fail "OpenClaw does not read sandbox mode non-main after the fix"
    grep -q 'this comment must survive' "$cfg" || fail "the edit dropped the operator's comment"
    expect_count 0 agent.sandbox-off

    step "agent.gateway-exposed: bind the gateway to loopback"
    expect_count 1 agent.gateway-exposed
    svc=$(jq -r '[.findings[] | select(.id == "agent.gateway-exposed")][0].service' /tmp/hv-scan.json)
    apply agent.gateway-exposed "$svc" 0
    [[ $(oc config get gateway.bind 2>/dev/null) == *loopback* ]] || fail "OpenClaw does not read gateway.bind loopback after the fix"
    expect_count 0 agent.gateway-exposed
    expect_count 0 agent.auth-disabled

    rollback_latest agent.gateway-exposed
    rollback_latest agent.sandbox-off
    [[ $(oc config get gateway.bind 2>/dev/null) == *lan* ]] || fail "OpenClaw does not read the original bind after rolling back"
    expect_count 1 agent.gateway-exposed
}

# What OpenClaw binds to when gateway.bind is not set. hostveil assumes
# loopback; one published guide says 0.0.0.0. Observed and printed here, not
# asserted, until the answer is known.
observe_openclaw_default_bind() {
    local home
    home=$(getent passwd "$OC_USER" | cut -d: -f6)
    printf '{\n  "gateway": {"auth": {"mode": "token", "token": "e2e-observe-only-0123456789"}},\n}\n' >"$home/.openclaw/openclaw.json"
    chown "$OC_USER" "$home/.openclaw/openclaw.json"
    (runuser -u "$OC_USER" -- timeout 40 openclaw gateway >/tmp/oc-gateway.log 2>&1 &)
    sleep 25
    printf '\n== observed: listeners of the OpenClaw gateway with gateway.bind unset\n'
    ss -ltnp | grep -E 'openclaw|node|18789' || echo "(nothing listening)"
    tail -20 /tmp/oc-gateway.log || true
}

# --- Proxmox -------------------------------------------------------------------

# Not a Proxmox host: there is no installing one on a CI runner. What the fix
# does is rewrite an apt source, so what is checked is that apt, against the
# real Proxmox repositories, refuses the enterprise source and accepts the one
# the fix writes. /etc/pve and pvesubscription are faked so the checker runs.
scenario_proxmox() {
    local codename src
    codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release)
    mkdir -p /etc/pve
    printf '#!/bin/sh\necho "status: notfound"\n' >/usr/local/bin/pvesubscription
    chmod +x /usr/local/bin/pvesubscription
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates jq >/dev/null
    case $codename in
    bookworm)
        curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg" -o /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg
        src=/etc/apt/sources.list.d/pve-enterprise.list
        echo "deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise" >"$src"
        ;;
    trixie)
        curl -fsSL "https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg" -o /usr/share/keyrings/proxmox-archive-keyring.gpg
        src=/etc/apt/sources.list.d/pve-enterprise.sources
        printf 'Types: deb\nURIs: https://enterprise.proxmox.com/debian/pve\nSuites: trixie\nComponents: pve-enterprise\nSigned-By: /usr/share/keyrings/proxmox-archive-keyring.gpg\n' >"$src"
        ;;
    *) fail "no Proxmox release for $codename" ;;
    esac
    if apt-get update >/tmp/apt-before.log 2>&1 &&
        ! grep -qE '401|Unauthorized' /tmp/apt-before.log; then
        cat /tmp/apt-before.log
        fail "the enterprise repository answered without a subscription; the seed is not the case the fix is for"
    fi

    step "proxmox.enterprise-repo-unsubscribed: switch to no-subscription ($codename)"
    expect_count 1 proxmox.enterprise-repo-unsubscribed
    apply proxmox.enterprise-repo-unsubscribed
    grep -q 'download.proxmox.com' "$src" || fail "the source does not point at download.proxmox.com"
    apt-get update >/tmp/apt-after.log 2>&1 || { cat /tmp/apt-after.log; fail "apt update fails with the rewritten source"; }
    grep -qE 'download.proxmox.com.*(InRelease|Release)' /tmp/apt-after.log || { cat /tmp/apt-after.log; fail "apt did not fetch the no-subscription repository"; }
    apt-cache policy | grep -q 'download.proxmox.com/debian/pve' || fail "apt does not list the no-subscription repository"
    expect_count 0 proxmox.enterprise-repo-unsubscribed
}

# --- reboot --------------------------------------------------------------------

# Never applied: it would take the host down. What is checked is what the
# operator is shown before saying yes.
scenario_reboot_preview() {
    step "updates.reboot-required: the preview says what will run and how to cancel it"
    touch /var/run/reboot-required
    expect_count 1 updates.reboot-required
    printf 'n\n' | "$HV" fix updates.reboot-required >/tmp/hv-reboot.txt 2>&1 || true
    grep -q 'shutdown -r +1' /tmp/hv-reboot.txt || fail "the preview does not show the scheduled reboot"
    grep -q 'shutdown -c' /tmp/hv-reboot.txt || fail "the preview does not say how to cancel"
    rm -f /var/run/reboot-required
}

case ${1:-} in
accounts) scenario_accounts ;;
owner) scenario_owner ;;
compose) scenario_compose ;;
dockerd) scenario_dockerd ;;
dockerd-revert) scenario_dockerd_revert ;;
systemd) scenario_systemd ;;
nginx) scenario_nginx ;;
reboot-preview) scenario_reboot_preview ;;
ufw) scenario_ufw ;;
k3s) scenario_k3s ;;
caddy) scenario_caddy ;;
traefik) scenario_traefik ;;
openclaw) scenario_openclaw && observe_openclaw_default_bind ;;
proxmox) scenario_proxmox ;;
*)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
printf '\nok %s\n' "$1"
