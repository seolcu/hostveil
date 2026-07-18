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
  sudo hostveil scan  # see the findings
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

```bash
cd demo
vagrant up                 # build + provision (first run downloads the box + images)
vagrant ssh                # SSH into the vulnerable server
```

Inside the VM:
```bash
sudo hostveil scan                 # scored report across all domains
sudo hostveil                      # interactive TUI
sudo hostveil serve --addr 0.0.0.0:8787   # web dashboard (see below)
```
> Run hostveil with **sudo** so it can read root-owned config
> (`/etc/ssh/sshd_config`) and apply fixes. Without sudo, those domains are
> skipped with a clear message — which is itself a nice thing to show.

**Web dashboard**: port 8787 is forwarded to the host, so once
`hostveil serve` is running in the VM, open **<http://localhost:8787>** in
your normal browser.

hostveil is built from the mounted repo (`/hostveil`), so it always reflects
your **current local source**. Changed the code? `vagrant provision` (or just
rebuild inside: `cd /hostveil && sudo /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil`).

---

## Suggested demo script (5 minutes)

1. **Scan** — `sudo hostveil scan`
   Score is low; findings are grouped by severity with plain-language
   descriptions across Docker/Compose, SSH, firewall, auto-updates, and CVEs.
2. **Explain one** — `sudo hostveil explain compose.ds018 --service redis`
   ("a database exposed to the whole internet").
3. **Fix with a preview** — `sudo hostveil fix ssh.rootlogin`
   Shows the exact diff, backs up the file, applies it. Then
   `sudo hostveil rollback <id>` restores it byte-for-byte.
4. **Fix everything safe** — `sudo hostveil fix --all`
   Watch the score jump.
5. **Re-scan** — `sudo hostveil scan` shows what's now *resolved*.
6. **(Optional) Web** — `sudo hostveil serve --addr 0.0.0.0:8787`, open
   <http://localhost:8787>, click a finding, preview + apply from the browser.

Judges can poke around and see it's a real server: `docker ps`,
`systemctl status ssh`, `sudo ufw status`.

---

## Reset between demo runs

Take a snapshot right after the first provision, then restore it to get a
pristine vulnerable server every time:

```bash
vagrant snapshot save clean       # once, after the first `vagrant up`
# ... demo, apply fixes ...
vagrant snapshot restore clean    # back to the original vulnerable state
```

Tear it down completely with `vagrant destroy`.

---

## What's deliberately vulnerable

| Domain | Seeded problem | Example finding |
|---|---|---|
| Docker/Compose | Portainer & Watchtower mount `docker.sock`; Redis/Postgres published on `0.0.0.0`; a privileged container with `SYS_ADMIN`; hardcoded DB/admin passwords; old images | `compose.ds016`, `ds018`, `ds019`, `ds001`, `dr005` |
| SSH | root login, password auth, empty passwords, weak `MaxAuthTries`, X11 forwarding | `ssh.rootlogin`, `ssh.passwordauth`, … |
| Firewall | `ufw` installed but inactive | `firewall.inactive` |
| Auto-updates | unattended-upgrades disabled | `updates.disabled` |
| CVEs | old image tags (redis 6.0, postgres 13, jellyfin 10.8, nextcloud 24, portainer 2.9) | `cve.*` (needs Trivy, installed in the VM) |

The stacks live in `stacks/`, the weak SSH snippet in `seed/`, and the whole
build lives in `Vagrantfile` + `provision.sh`.
