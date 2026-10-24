#!/usr/bin/env bash
# Drive the forensics experiments end to end from the host.
#
#   ./run.sh up        build hostveil for linux/amd64, boot and provision the VM, snapshot "clean"
#   ./run.sh e1        experiment 1: every tool on the clean VM, then on the VM with every scenario
#   ./run.sh e2        experiment 2: the RCE + SSH scenarios and a reboot, on a stock VM and on a readied one
#   ./run.sh score     score results/ against truth.json into results/summary.json
#   ./run.sh destroy
#
# Every experiment starts from the "clean" snapshot. Results land in results/.
set -Eeuo pipefail
cd "$(dirname "$0")"
REPO=$(cd ../.. && pwd)
mkdir -p results .bin

# The VM reaches the internet through a forward proxy on the host's
# loopback (HTTP_PROXY_PORT), carried in by an SSH reverse tunnel, for hosts
# whose libvirt NAT does not route. Without the variable, nothing is
# tunnelled and the VM uses its own network.
SSHCFG=.vagrant/ssh-config
tunnel() {
  [[ -n ${HTTP_PROXY_PORT:-} ]] || return 0
  pkill -f "R ${HTTP_PROXY_PORT}:127.0.0.1:${HTTP_PROXY_PORT} default" 2>/dev/null || true
  vagrant ssh-config > "$SSHCFG"
  # A snapshot taken while a tunnel was open restores its stale listener.
  ssh -F "$SSHCFG" default "sudo fuser -k ${HTTP_PROXY_PORT}/tcp >/dev/null 2>&1; true"
  ssh -F "$SSHCFG" -fN -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
      -R "${HTTP_PROXY_PORT}:127.0.0.1:${HTTP_PROXY_PORT}" default
}
vm() { vagrant ssh -c "$1" -- -q; }
fetch() { rm -rf "results/$1"; vm "sudo tar -C /root/results -cz $1" | tar -C results -xz; }
restore() { vagrant snapshot restore clean --no-provision >/dev/null; vagrant rsync >/dev/null; tunnel; }

build() {
  (cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
     -ldflags "-X main.version=$(git describe --tags --always)-forensics" -o scripts/forensics/.bin/hostveil ./cmd/hostveil)
}

case ${1:-} in
  up)
    build
    vagrant up --provider=libvirt
    vagrant snapshot save clean --force
    ;;
  e1)
    build; restore
    # rkhunter compares file properties against a baseline it records here,
    # on the clean host — the condition under which it is meant to be used.
    vm "sudo rkhunter --propupd --nocolors >/dev/null 2>&1; sudo /fx/run-tools.sh e1-clean"
    vm "sudo /fx/seed.sh all && sudo /fx/run-tools.sh e1-attacked"
    fetch e1-clean; fetch e1-attacked
    ;;
  e2)
    build
    for arm in default ready; do
      restore
      [[ $arm == ready ]] && vm "sudo /fx/readiness.sh"
      vm "sudo /fx/seed.sh e2"
      vagrant reload --no-provision >/dev/null
      vagrant rsync >/dev/null
      tunnel
      vm "sudo /fx/run-tools.sh e2-$arm triage"
      fetch "e2-$arm"
      [[ $arm == ready ]] && vm "sudo cat /root/readiness-before.json" > results/e2-ready/readiness-before.json && \
                             vm "sudo cat /root/readiness-after.json" > results/e2-ready/readiness-after.json
    done
    ;;
  score) python3 score.py ;;
  destroy) vagrant destroy -f ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
