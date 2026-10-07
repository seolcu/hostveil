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

# --- reboot ------------------------------------------------------------------

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
*)
    sed -n '2,20p' "$0"
    exit 2
    ;;
esac
printf '\nok %s\n' "$1"
