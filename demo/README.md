# hostveil demo — a vulnerable home server in one command

This directory is a **reproducible, code-defined test/demo environment** for
hostveil: a real Ubuntu 24.04 server, deliberately misconfigured the way a
non-expert self-hoster's box would be, running inside a VM.

It exists so you can try hostveil (and demo it) **without touching a real
device**, on any laptop, and so teammates get the exact same environment
from a `git clone`.

```
cd demo
vagrant up            # boots + provisions the vulnerable server (first run: a few minutes)
vagrant ssh           # you're now on the "home server"
  hostveil scan       # see the findings (auto-elevates with sudo)
```

Everything is **real** — real Docker with real running stacks, real weak SSH
config, real firewall state, real package config. Every hostveil domain
fires authentically, and fixes really change the system (and roll back).

---

## One-time setup

You need **Vagrant** + a **provider** (the thing that runs the VM).

### This Fedora dev machine (KVM — fastest)
```bash
sudo dnf install -y vagrant vagrant-libvirt qemu-kvm libvirt virt-install
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"     # then log out/in (or: newgrp libvirt)
```

### macOS / Windows / other Linux (teammates)
1. Install **Vagrant**: <https://developer.hashicorp.com/vagrant/install>
2. Install **VirtualBox**: <https://www.virtualbox.org/wiki/Downloads>

That's it — the same `Vagrantfile` picks libvirt or VirtualBox automatically.

> **Apple Silicon (M1–M4) Macs**: VirtualBox/amd64 boxes don't run there.
> Use a VM tool with an arm64 Ubuntu box (e.g. UTM/qemu or `vagrant` with the
> `qemu`/`parallels` provider), or run the demo on an Intel/AMD machine. The
> `provision.sh` already picks the right Go build for the VM's architecture.

---

## Run it

Nothing auto-starts — you bring the demo up **only when you want it** with
the `run.sh` helper, and shut it down when you're done:

```bash
cd demo
./run.sh up        # boot the VM + start the vulnerable stacks (first run downloads the box + images)
./run.sh scan      # scored report across all domains
./run.sh web       # dashboard at http://localhost:8787 (Ctrl-C to stop)
./run.sh shell     # a shell on the demo server — then e.g. `hostveil`
./run.sh halt      # shut the VM down; nothing keeps running
```

Prefer raw Vagrant? `vagrant up` / `vagrant ssh` work too (run
`./run.sh up` once after a boot to start the stacks — they intentionally
have no restart policy, so they don't come back on their own).

> Inside the VM, plain `hostveil` re-executes itself under **sudo**
> automatically so it can read root-owned config (`/etc/ssh/sshd_config`) and
> apply fixes — the prompt you see is sudo's own. To instead show the graceful
> non-root behaviour, run `HOSTVEIL_NO_SUDO=1 hostveil scan`: the root-owned
> domains are skipped with a clear message and the score is renormalized —
> itself a nice thing to demo.

**Web dashboard**: port 8787 is forwarded to the host, so while
`./run.sh web` is running, open **<http://localhost:8787>** in your browser.

hostveil is built from the mounted repo (`/hostveil`), so it always reflects
your **current local source**. Changed the code? `vagrant provision` (or just
rebuild inside: `cd /hostveil && sudo /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil`).

---

## Suggested demo script (5 minutes)

1. **Scan** — `hostveil scan`
   Score is low; findings are grouped by severity with plain-language
   descriptions across Docker/Compose, SSH, firewall, auto-updates, and CVEs.
2. **Explain one** — `hostveil explain compose.ds018 --service redis`
   ("a database exposed to the whole internet").
3. **Fix with a preview** — `hostveil fix ssh.rootlogin`
   Shows the exact diff, backs up the file, applies it. Then
   `hostveil rollback <id>` restores it byte-for-byte.
4. **Fix everything safe** — `hostveil fix --all`
   Watch the score jump.
5. **Re-scan** — `hostveil scan` shows what's now *resolved*.
6. **(Optional) Web** — `hostveil serve --addr 0.0.0.0:8787`, open
   <http://localhost:8787>, click a finding, preview + apply from the browser.

Judges can poke around and see it's a real server: `docker ps`,
`systemctl status ssh`, `sudo ufw status`.

---

## Reset between demo runs

Take a snapshot once the server is up, then restore it to get a pristine
vulnerable server every time:

```bash
./run.sh snapshot     # once, after `./run.sh up` — saves the "clean" baseline
# ... demo, apply fixes ...
./run.sh reset        # back to the original vulnerable state + stacks restarted
```

Tear it down completely with `./run.sh destroy`.

---

## Troubleshooting

**The VM has no internet during `vagrant up` (Linux + libvirt + Docker on the host).**
If the host also runs Docker, Docker sets the kernel's `FORWARD` policy to
DROP, which blocks the libvirt VM's NAT traffic (you'll see apt/curl time
out inside the VM). Allow the VM's bridge to forward and masquerade out:

```bash
sudo firewall-cmd --zone="$(firewall-cmd --get-default-zone)" --add-masquerade
sudo firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i virbr0 -j ACCEPT
sudo firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -o virbr0 -j ACCEPT
```

These apply immediately. To keep them across reboots, append `--permanent`
to each (then `sudo firewall-cmd --reload`). Then re-run `vagrant provision`.
This does **not** affect teammates using VirtualBox (macOS/Windows), whose
NAT is independent of the host firewall.

## What's deliberately vulnerable

| Domain | Seeded problem | Example finding |
|---|---|---|
| Docker/Compose | Portainer & Watchtower mount `docker.sock`; Redis/Postgres published on `0.0.0.0`; a privileged container with `SYS_ADMIN`; hardcoded DB/admin passwords; old images | `compose.ds016`, `ds018`, `ds019`, `ds001`, `dr005` |
| SSH | root login, password auth, empty passwords, weak `MaxAuthTries`, X11 forwarding | `ssh.rootlogin`, `ssh.passwordauth`, … |
| Firewall | `ufw` installed but inactive | `firewall.inactive` |
| Auto-updates | unattended-upgrades disabled | `updates.disabled` |
| Exposed services | a native (non-Docker) Redis bound to `0.0.0.0` | `ports.exposed-datastore` |
| Accounts | a second UID-0 account (`backdoor`) and a passwordless login account (`demo_nopass`) | `accounts.uid0`, `accounts.emptypassword` |
| File permissions | `/etc/shadow` made world-readable | `fileperms.shadow` |
| CVEs | old image tags (redis 6.0, postgres 13, jellyfin 10.8, nextcloud 24, portainer 2.9) | `cve.*` (needs Trivy, installed in the VM) |

The stacks live in `stacks/`, the weak SSH snippet in `seed/`, and the whole
build lives in `Vagrantfile` + `provision.sh`.
