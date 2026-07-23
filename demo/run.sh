#!/usr/bin/env bash
# Easy on-demand control of the hostveil demo VM. Nothing auto-starts —
# you bring the demo up only when you want it, and halt it when done.
#
#   ./run.sh up        boot the VM + rebuild hostveil + start the vulnerable stacks
#   ./run.sh build     re-sync the repo and rebuild hostveil in the VM
#   ./run.sh scan      run `hostveil scan` on the demo server
#   ./run.sh web       serve the dashboard at http://localhost:8787 (Ctrl-C to stop)
#   ./run.sh shell     open a shell on the demo server (then e.g. `hostveil`)
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

# Re-sync the repo and rebuild hostveil inside the VM. `vagrant up` only runs
# provisioners the first time a VM is created, and the build lives in
# provision.sh — so without this every later boot leaves the VM running
# whatever binary the *first* provision produced, silently testing stale code.
rebuild() {
  vagrant rsync
  vagrant ssh -c 'cd /hostveil && sudo /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil'
}

case "${1:-up}" in
  up)
    vagrant up
    echo "==> rebuilding hostveil from the synced source…"
    rebuild
    echo "==> starting vulnerable stacks…"
    start_stacks
    echo "Ready.  ./run.sh scan   |   ./run.sh web   |   ./run.sh shell"
    ;;
  build)
    rebuild
    echo "Rebuilt /usr/local/bin/hostveil from the current working tree."
    ;;
  scan)    vagrant ssh -c "sudo hostveil scan ${2:-}" ;;
  web)
    # 0.0.0.0 so Vagrant's NAT port-forward can reach the listener; the
    # browser still addresses it as localhost, which is what the dashboard's
    # Host allowlist checks. Open the tokenized URL hostveil prints below.
    echo "Dashboard: http://localhost:8787   (open the URL printed below — it carries the access token)"
    vagrant ssh -c "sudo hostveil serve --addr 0.0.0.0:8787"
    ;;
  shell)   vagrant ssh ;;
  snapshot) vagrant snapshot save clean && echo "Saved snapshot 'clean'." ;;
  reset)
    vagrant snapshot restore clean
    # The snapshot carries whatever binary was current when it was taken, so
    # rebuild to get back in step with the working tree.
    echo "==> rebuilding hostveil from the synced source…"
    rebuild
    echo "==> restarting vulnerable stacks…"
    start_stacks
    echo "Restored to the clean vulnerable baseline."
    ;;
  halt)    vagrant halt ;;
  destroy) vagrant destroy -f ;;
  *)
    echo "usage: ./run.sh {up|build|scan|web|shell|snapshot|reset|halt|destroy}" >&2
    exit 2
    ;;
esac
