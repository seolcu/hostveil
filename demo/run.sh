#!/usr/bin/env bash
# Easy on-demand control of the hostveil demo VM. Nothing auto-starts —
# you bring the demo up only when you want it, and halt it when done.
#
#   ./run.sh up        boot the VM + start the vulnerable stacks
#   ./run.sh scan      run `hostveil scan` on the demo server
#   ./run.sh web       serve the dashboard at http://localhost:8787 (Ctrl-C to stop)
#   ./run.sh shell     open a shell on the demo server (then e.g. `sudo hostveil`)
#   ./run.sh snapshot  save the current state as the clean baseline
#   ./run.sh reset     restore the clean baseline + restart stacks
#   ./run.sh halt      shut the VM down (nothing keeps running)
#   ./run.sh destroy   delete the VM entirely
set -euo pipefail
cd "$(dirname "$0")"
export VAGRANT_CWD="$PWD"

# Bring every stack up inside the VM (idempotent). Stacks have no restart
# policy on purpose, so they need starting after each boot.
start_stacks() {
  vagrant ssh -c 'for d in /opt/stacks/*/; do (cd "$d" && sudo docker compose up -d); done' 2>/dev/null
}

case "${1:-up}" in
  up)
    vagrant up
    echo "==> starting vulnerable stacks…"
    start_stacks
    echo "Ready.  ./run.sh scan   |   ./run.sh web   |   ./run.sh shell"
    ;;
  scan)    vagrant ssh -c "sudo hostveil scan ${2:-}" ;;
  web)
    echo "Dashboard: http://localhost:8787   (Ctrl-C to stop)"
    vagrant ssh -c "sudo hostveil serve --addr 0.0.0.0:8787"
    ;;
  shell)   vagrant ssh ;;
  snapshot) vagrant snapshot save clean && echo "Saved snapshot 'clean'." ;;
  reset)
    vagrant snapshot restore clean
    echo "==> restarting vulnerable stacks…"
    start_stacks
    echo "Restored to the clean vulnerable baseline."
    ;;
  halt)    vagrant halt ;;
  destroy) vagrant destroy -f ;;
  *)
    echo "usage: ./run.sh {up|scan|web|shell|snapshot|reset|halt|destroy}" >&2
    exit 2
    ;;
esac
