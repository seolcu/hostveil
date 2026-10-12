#!/usr/bin/env bash
# A disposable Ubuntu 24.04 or Fedora VM for scripts/e2e/individual.sh, on
# this machine.
#
# Usage:
#   scripts/e2e/vm.sh up                  # boot it (downloads the image once)
#   scripts/e2e/vm.sh run SCENARIO...     # build hostveil, copy it in, run the scenarios
#   scripts/e2e/vm.sh ssh [CMD...]        # get in, as the VM is now
#   scripts/e2e/vm.sh reset               # throw this run's changes away and boot clean
#   scripts/e2e/vm.sh down                # stop it
#
#   HOSTVEIL_BIN=/path/to/hostveil scripts/e2e/vm.sh run dockerd
#                                         # run a binary you built, e.g. an old tag
#   HOSTVEIL_E2E_DISTRO=fedora scripts/e2e/vm.sh up
#                                         # Fedora instead of Ubuntu (port 2223)
#
# Why it exists: the individual-only fixes restart daemons and edit /etc, so
# their scenarios need systemd as PID 1 and a real Docker, which a rootless
# container does not give. They could only run in CI, and debugging them there
# took thirteen round trips of two to six minutes each, eight of them failures,
# with the cause dug out of logs afterwards. This is the same Ubuntu release
# the ubuntu-latest runner uses, the same script, and a shell into the VM the
# moment a scenario fails — which CI can never give.
#
# It edits only the VM. That is what makes it the safe local path AGENTS.md
# asks for: never run these scenarios on your own machine.
#
# The proxmox scenario wants Debian, not Ubuntu; run it in a container:
#   podman run --rm -e HOSTVEIL_ASSUME_HOST=1 -v "$PWD:/src:ro,Z" debian:13 \
#     bash -c 'apt-get update -qq && /src/scripts/e2e/individual.sh proxmox'

set -euo pipefail

cd "$(dirname "$0")/../.." || exit 1

DISTRO=${HOSTVEIL_E2E_DISTRO:-ubuntu}
# Each distribution gets its own cache, port and provisioned disk, so an
# Ubuntu and a Fedora VM can be up side by side without one overwriting the
# other's base image.
case $DISTRO in
ubuntu)
    # The release the ubuntu-latest runner uses, provisioned with what the
    # runner already has, so a scenario passing here means what it means in CI.
    IMAGE_URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
    VMUSER=ubuntu
    DEFAULT_PORT=2222
    PACKAGES="docker.io, docker-compose-v2, jq, curl, ufw, openssh-server, python3, xz-utils"
    ;;
fedora)
    # No CI runner is Fedora, and until this the project had never booted a
    # Fedora host at all: the distros job scans a container, and
    # scripts/measure/Vagrantfile records that the Fedora box would not come
    # up. firewalld is what Fedora ships enabled, so it stays.
    IMAGE_URL=https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
    VMUSER=fedora
    DEFAULT_PORT=2223
    PACKAGES="moby-engine, docker-compose, jq, curl, firewalld, openssh-server, python3, xz"
    ;;
*)
    printf 'vm.sh: HOSTVEIL_E2E_DISTRO must be ubuntu or fedora, not %s\n' "$DISTRO" >&2
    exit 1
    ;;
esac

CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/hostveil/e2e/$DISTRO
STATE=$CACHE/vm
PORT=${HOSTVEIL_E2E_PORT:-$DEFAULT_PORT}
# Guest ports a scenario can reach from outside the VM. Each is forwarded from
# 127.0.0.1:OUTSIDE+port on this machine, and QEMU's user network answers the
# guest's 10.0.2.2 with this machine's loopback, so a scenario connecting to
# 10.0.2.2:OUTSIDE+port leaves the VM and comes back in through its network
# card, where the firewall applies. That is the one view of an exposed port
# that is not the host's own opinion of itself.
PROBE_PORTS=(6379 8080 9000)
OUTSIDE=$(((PORT - 2222 + 1) * 10000))
BASE=$CACHE/${IMAGE_URL##*/}
# Provisioning — Docker, a firewall, node — takes minutes, and a reset that
# paid it every time would put back the wait this script exists to remove. So
# the first boot provisions, powers off, and keeps its disk as PROVISIONED;
# every run after that is a throwaway overlay on top of it. Delete $CACHE to
# provision afresh.
PROVISIONED=$CACHE/provisioned.qcow2
SEED=$CACHE/seed.iso
KEY=$CACHE/id_ed25519

die() {
    printf 'vm.sh: %s\n' "$*" >&2
    exit 1
}

vssh() {
    ssh -i "$KEY" -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR -o ConnectTimeout=5 "$VMUSER@127.0.0.1" "$@"
}

vscp() {
    scp -i "$KEY" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR "$@"
}

running() {
    [[ -f $STATE/pid ]] && kill -0 "$(cat "$STATE/pid")" 2>/dev/null
}

# The cloud-config installs PACKAGES, starts Docker, and puts a node new
# enough for OpenClaw in /usr/local, the same on every distribution.
seed() {
    local pub
    pub=$(cat "$KEY.pub")
    cat >"$CACHE/user-data" <<EOF
#cloud-config
users:
  - name: $VMUSER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: ["$pub"]
package_update: true
packages: [$PACKAGES]
runcmd:
  - systemctl enable --now docker
  - |
    v=\$(curl -fsSL https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt | awk '/linux-x64.tar.xz/ {print \$2}')
    curl -fsSL "https://nodejs.org/dist/latest-v24.x/\$v" | tar xJ -C /usr/local --strip-components=1
  - touch /var/lib/hostveil-e2e-ready
EOF
    printf 'instance-id: hostveil-e2e\nlocal-hostname: hostveil-e2e\n' >"$CACHE/meta-data"
    genisoimage -quiet -output "$SEED" -volid cidata -joliet -rock "$CACHE/user-data" "$CACHE/meta-data"
}

forwards() {
    local p
    for p in "${PROBE_PORTS[@]}"; do
        printf ',hostfwd=tcp:127.0.0.1:%s-:%s' "$((OUTSIDE + p))" "$p"
    done
}

boot() {
    local disk=$1 limit=$2 start=$SECONDS
    qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 4 \
        -drive "file=$disk,if=virtio" \
        -drive "file=$SEED,media=cdrom" \
        -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22$(forwards)" -device virtio-net-pci,netdev=n0 \
        -display none -serial "file:$STATE/serial.log" \
        -daemonize -pidfile "$STATE/pid"
    printf 'booting'
    until vssh test -f /var/lib/hostveil-e2e-ready 2>/dev/null; do
        ((SECONDS - start < limit)) || die "the VM was not ready in ${limit}s; see $STATE/serial.log"
        printf '.'
        sleep 3
    done
    printf ' ready in %ss\n' "$((SECONDS - start))"
}

# provision builds PROVISIONED once: boot the cloud image with the seed, wait
# for cloud-init to finish, and power off so the disk is consistent.
provision() {
    echo "provisioning the $DISTRO VM (once; takes several minutes)…"
    [[ -f $BASE ]] || {
        curl -fL --progress-bar -o "$BASE.part" "$IMAGE_URL" && mv "$BASE.part" "$BASE"
    }
    [[ -f $KEY ]] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
    seed
    qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$PROVISIONED.part" 20G
    boot "$PROVISIONED.part" 1800
    vssh sudo poweroff || true
    local pid
    pid=$(cat "$STATE/pid")
    while kill -0 "$pid" 2>/dev/null; do sleep 1; done
    rm -f "$STATE/pid"
    mv "$PROVISIONED.part" "$PROVISIONED"
}

cmd_up() {
    if running; then
        echo "already running on port $PORT"
        return
    fi
    for t in qemu-system-x86_64 qemu-img genisoimage ssh scp; do
        command -v "$t" >/dev/null || die "$t is not installed"
    done
    [[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not usable by $(id -un)"
    mkdir -p "$STATE"
    [[ -f $PROVISIONED ]] || provision
    [[ -f $STATE/disk.qcow2 ]] ||
        qemu-img create -q -f qcow2 -F qcow2 -b "$PROVISIONED" "$STATE/disk.qcow2" 20G
    boot "$STATE/disk.qcow2" 300
}

cmd_down() {
    if running; then
        kill "$(cat "$STATE/pid")"
        echo "stopped"
    fi
    rm -f "$STATE/pid"
}

cmd_reset() {
    cmd_down
    rm -f "$STATE/disk.qcow2"
    cmd_up
}

cmd_ssh() {
    running || die "not running; scripts/e2e/vm.sh up"
    vssh -t "$@"
}

cmd_run() {
    (($# > 0)) || die "name at least one scenario; see scripts/e2e/individual.sh"
    running || cmd_up
    local bin=${HOSTVEIL_BIN:-}
    if [[ -z $bin ]]; then
        bin=$STATE/hostveil
        CGO_ENABLED=0 go build -o "$bin" ./cmd/hostveil
    fi
    vscp "$bin" scripts/e2e/individual.sh "$VMUSER@127.0.0.1:/tmp/" >/dev/null
    vssh "sudo install -m 0755 /tmp/$(basename "$bin") /usr/local/bin/hostveil"

    # In CI, a failure inside the VM writes its summary there; carry it out to
    # the job's own, so it reads the same as a scenario run on the runner.
    local summary=""
    [[ -n ${GITHUB_STEP_SUMMARY:-} ]] && summary=GITHUB_STEP_SUMMARY=/tmp/hv-summary.md

    local results=() s start rc=0
    for s in "$@"; do
        start=$SECONDS
        if vssh "sudo -E env $summary HOSTVEIL_E2E_OUTSIDE=10.0.2.2:$OUTSIDE HOSTVEIL=/usr/local/bin/hostveil PATH=\$PATH bash /tmp/individual.sh $s"; then
            results+=("ok   $s ($((SECONDS - start))s)")
        else
            results+=("FAIL $s ($((SECONDS - start))s)")
            rc=1
        fi
    done
    if [[ -n $summary ]]; then
        vssh "sudo cat /tmp/hv-summary.md 2>/dev/null" >>"$GITHUB_STEP_SUMMARY" || true
    fi
    printf '\n'
    printf '%s\n' "${results[@]}"
    ((rc == 0)) || printf '\nthe VM is as the failure left it: scripts/e2e/vm.sh ssh\n'
    return "$rc"
}

# One function, called on the last line: bash reads a script as it runs, and
# a run lasts long enough to edit this file in the middle of one, which
# otherwise ends it at whatever the edit left half-read.
main() {
    case ${1:-} in
    up) cmd_up ;;
    down) cmd_down ;;
    reset) cmd_reset ;;
    ssh) shift && cmd_ssh "$@" ;;
    run) shift && cmd_run "$@" ;;
    *)
        sed -n '2,15p' "$0"
        exit 2
        ;;
    esac
}

main "$@"
