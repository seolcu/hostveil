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

# An unprivileged libvirt client resolves to qemu:///session, and this demo
# cannot run there: session mode has no management network, so the VM boots,
# never gets an address, and vagrant gives up several minutes later with "not
# yet ready for SSH". What it leaves behind is worse than the failure — a
# defined domain with no Vagrant metadata, so the *next* attempt refuses with
# "Name demo_default of domain about to create is already taken", which names
# nothing that led there and no way out. The forwarded port and the NAT the
# Vagrantfile assumes are system-connection features besides.
#
# Set here rather than written down in the README, because neither message
# describes what went wrong and every command below shells out to vagrant. An
# explicit LIBVIRT_DEFAULT_URI wins, so a session setup somebody has made to
# work is left alone.
if [ "$(uname -s)" = Linux ] && [ -z "${LIBVIRT_DEFAULT_URI:-}" ]; then
  export LIBVIRT_DEFAULT_URI=qemu:///system
fi

# Reaching that connection needs libvirtd running and this account in the
# libvirt group — the one-time setup in README.md, both of which otherwise
# surface late and in somebody else's words. Skipped where the question
# cannot be answered (no virsh) or where libvirt may not be the provider at
# all (VirtualBox installed, macOS, a URI you set yourself).
if [ "${LIBVIRT_DEFAULT_URI:-}" = qemu:///system ] &&
  command -v virsh >/dev/null && ! command -v VBoxManage >/dev/null &&
  ! virsh -c qemu:///system version >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Cannot reach libvirt at qemu:///system, so there is nothing to run the VM.
The usual two reasons, and their one-time fixes:

  sudo systemctl enable --now libvirtd     # the daemon is not running
  sudo usermod -aG libvirt "$USER"         # you are not in the group
                                           # (then log out and back in)

See "One-time setup" in demo/README.md.
EOF
  exit 1
fi

# vagrant-libvirt names the domain after this directory. Recomputed rather
# than hardcoded so a renamed checkout still gets a true error message.
domain="$(basename "$PWD")_default"

# vagrant-libvirt implements the forwarded port with a long-lived SSH -L
# process. A hard host shutdown or removing an orphan domain with virsh can
# leave that process behind: it still accepts localhost:8787, then forwards to
# the IP of a VM that no longer exists, so a browser waits forever while the
# next `vagrant up` appears to have configured the port successfully.
#
# Only remove a tunnel whose command names this checkout's generated private
# key, and only when its domain is not running. That makes the target narrower
# than "whatever owns 8787" and leaves a live demo entirely alone.
clear_stale_forward() {
  [ "$(uname -s)" = Linux ] || return 0
  command -v virsh >/dev/null || return 0

  state="$(virsh -c "${LIBVIRT_DEFAULT_URI:-qemu:///system}" domstate "$domain" 2>/dev/null || true)"
  [ "$state" = running ] && return 0

  key="$PWD/.vagrant/machines/default/libvirt/private_key"
  pids="$(ps -eo pid=,comm=,args= 2>/dev/null | awk -v key="IdentityFile=\"$key\"" '
    $2 == "ssh" && index($0, key) && index($0, " -L *:8787:") { print $1 }
  ')"
  [ -n "$pids" ] || return 0

  echo "==> stopping stale demo port forward on localhost:8787…"
  # Each PID came from an exact command-line match above, not from a port-wide
  # kill. Split on newlines/spaces deliberately; kill accepts the resulting
  # PID list as separate arguments.
  # shellcheck disable=SC2086
  kill $pids
}

# The libvirt forwarder binds IPv4 and IPv6 separately. If another process
# already owns only one of them, `vagrant up` can still print a successful
# 8787 mapping after binding the other; localhost then reaches one service or
# the other depending on address-family order. Refuse that split-brain state
# before booting. A running demo is exempt because its own forwarder is the
# expected listener and `up` is intentionally idempotent.
require_free_web_port() {
  state="$(vagrant status --machine-readable 2>/dev/null | awk -F, '$3 == "state" { print $4; exit }')"
  [ "$state" = running ] && return 0

  used=false
  if command -v ss >/dev/null; then
    ss -H -ltn 'sport = :8787' 2>/dev/null | grep -q . && used=true
  elif command -v lsof >/dev/null; then
    lsof -nP -iTCP:8787 -sTCP:LISTEN >/dev/null 2>&1 && used=true
  fi
  [ "$used" = false ] && return 0

  cat >&2 <<'EOF'
Host port 8787 is already in use, so the demo dashboard cannot be forwarded
there. Stop the process using it and run this again. The port is not changed
silently because every demo command and URL intentionally uses localhost:8787.
EOF
  exit 1
}

# A defined domain that Vagrant has no record of is the wreckage of a
# creation that did not finish — a host suspend, a Ctrl-C, or the session-URI
# trap above before it was closed. Vagrant's own words for it are "already
# taken", which reads as a name collision and sends you looking for the wrong
# thing. Reported rather than removed: it is a virtual machine, and deleting
# one is not a thing to guess at on somebody's behalf.
warn_orphan_domain() {
  [ -f .vagrant/machines/default/libvirt/id ] && return 0
  command -v virsh >/dev/null || return 0
  virsh dominfo "$domain" >/dev/null 2>&1 || return 0
  # -c spelled out because the URI this script exports does not survive into
  # the shell reading the message, where plain virsh would go looking on the
  # session connection and report no such domain.
  cat >&2 <<EOF
A libvirt domain named $domain exists, but Vagrant has no record of it, so it
will refuse to create one over the top. It holds nothing you can get at: an
unfinished VM never had a key inserted, so there is no way to log into it.
Remove it and run this again:

  virsh -c ${LIBVIRT_DEFAULT_URI:-qemu:///system} destroy $domain    # only if it is still running
  virsh -c ${LIBVIRT_DEFAULT_URI:-qemu:///system} undefine $domain --remove-all-storage
EOF
  exit 1
}

# Bring every stack up inside the VM (idempotent). Stacks have no restart
# policy on purpose, so they need starting after each boot.
start_stacks() {
  # Single quotes on purpose: $d is the guest's loop variable and must reach
  # the guest shell unexpanded. Expanding it here would send one empty path.
  # shellcheck disable=SC2016
  vagrant ssh -c 'for d in /opt/stacks/*/; do (cd "$d" && sudo docker compose up -d); done' 2>/dev/null
}

# Re-sync the repo and rebuild hostveil inside the VM. `vagrant up` only runs
# provisioners the first time a VM is created, and the build lives in
# provision.sh — so without this every later boot leaves the VM running
# whatever binary the *first* provision produced, silently testing stale code.
rebuild() {
  vagrant rsync
  vagrant ssh -c 'cd /hostveil && sudo /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil' && return 0

  # A build that cannot find its compiler usually means provision.sh never
  # reached the end — the first `up` timed out installing something, which on
  # a host running Docker is the norm rather than the exception (see
  # Troubleshooting in README.md). Vagrant records the VM as provisioned
  # anyway, so the next `up` skips straight past it and this build is the
  # first thing to notice, in words about Go. Costs an extra round trip only
  # on the path that has already failed.
  vagrant ssh -c 'test -x /usr/local/go/bin/go' >/dev/null 2>&1 && return 1
  cat >&2 <<'EOF'

There is no Go toolchain in the VM, so provisioning never finished — this is
a half-built machine, not a build failure. Finish it:

  vagrant provision

If it dies again at a download timing out, the VM has no route to the
internet: see "The VM has no internet during vagrant up" in demo/README.md.
EOF
  exit 1
}

case "${1:-up}" in
  up)
    clear_stale_forward
    warn_orphan_domain
    require_free_web_port
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
  halt)
    vagrant halt
    clear_stale_forward
    ;;
  destroy)
    vagrant destroy -f
    clear_stale_forward
    ;;
  *)
    echo "usage: ./run.sh {up|build|scan|web|shell|snapshot|reset|halt|destroy}" >&2
    exit 2
    ;;
esac
