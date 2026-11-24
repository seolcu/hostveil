# Hostveil demo: a vulnerable home server in one command

This directory is a **reproducible, code-defined test/demo environment** for
Hostveil: a real Ubuntu 24.04 server, misconfigured the way a
non-expert self-hoster's box would be, running inside a VM.

It exists so you can try Hostveil (and demo it) **without touching a real
device**, on any laptop, and so teammates get the exact same environment
from a `git clone`.

```
cd demo
./run.sh up           # boots + provisions the vulnerable server (first run: a few minutes)
./run.sh shell        # you're now on the "home server"
  hostveil scan       # see the findings (auto-elevates with sudo)
```

Everything is **real**: real Docker with real running stacks, real weak SSH
config, real firewall state, real package config. Every Hostveil domain
fires authentically, and fixes really change the system (and roll back).

---

## One-time setup

You need **Vagrant** + a **provider** (the thing that runs the VM).

### This Fedora dev machine (KVM: fastest)
```bash
sudo dnf install -y vagrant vagrant-libvirt qemu-kvm libvirt virt-install
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"     # then log out/in (or: newgrp libvirt)
```

### macOS / Windows / other Linux (teammates)
1. Install **Vagrant**: <https://developer.hashicorp.com/vagrant/install>
2. Install **VirtualBox**: <https://www.virtualbox.org/wiki/Downloads>
3. `vagrant plugin install vagrant-disksize`

That's it: the same `Vagrantfile` picks libvirt or VirtualBox automatically.

> **On the disk.** The box ships 8.7GB and this demo does not fit: the seven
> outdated images are 3.8GB and Trivy's vulnerability DB is another 1.2GB. The
> `Vagrantfile` asks for 24GB, which is sparse and costs what it uses. libvirt
> does this on its own; VirtualBox needs the plugin above, and without it the
> demo still comes up but the CVE domain runs out of room: Trivy unpacks an
> image to scan it, so the two 1.32GB images cannot be scanned at all, and a
> vulnerability score that skipped the heaviest images is *better* than the
> truth. Hostveil says "partial" when this happens; the number beside it is
> still wrong.
>
> An existing VM keeps the disk it was built with. `./run.sh destroy` then
> `./run.sh up` to pick up the new size.
>
> **On memory.** The VM gets 2GB. If a scan reports `CVEs partial: ... signal:
> killed`, Trivy ran out of memory next to the stacks. Put
> `HOSTVEIL_DEMO_MEMORY=4096` in `demo/.env` before the VM is first created. On a
> libvirt VM that already exists, set it with `virsh setmaxmem demo_default 4G
> --config` and `virsh setmem demo_default 4G --config` while the VM is off, then
> `./run.sh up`.

> **Apple Silicon (M1–M4) Macs**: VirtualBox/amd64 boxes don't run there.
> Use a VM tool with an arm64 Ubuntu box (e.g. UTM/qemu or `vagrant` with the
> `qemu`/`parallels` provider), or run the demo on an Intel/AMD machine. The
> `provision.sh` already picks the right Go build for the VM's architecture.

---

## Run it

Nothing auto-starts: you bring the demo up **only when you want it** with
the `run.sh` helper, and shut it down when you're done:

```bash
cd demo
./run.sh up        # boot the VM + rebuild Hostveil + start the stacks (first run downloads the box + images)
./run.sh build     # re-sync the repo and rebuild Hostveil in the VM (after editing code)
./run.sh scan      # scored report across all domains
./run.sh web       # dashboard at http://localhost:8787 (Ctrl-C to stop)
./run.sh shell     # a shell on the demo server, then e.g. `hostveil`
./run.sh halt      # shut the VM down; nothing keeps running
```

Prefer raw Vagrant? `vagrant up` / `vagrant ssh` work too (run
`./run.sh up` once after a boot to start the stacks: they intentionally
have no restart policy, so they don't come back on their own). **On Linux,
export `LIBVIRT_DEFAULT_URI=qemu:///system` first.** An unprivileged libvirt
client resolves to `qemu:///session`, which has no management network: the
VM boots, never gets an address, and Vagrant gives up minutes later with
*"not yet ready for SSH"*. `run.sh` sets it for you; raw `vagrant` does not.

> Inside the VM, plain `hostveil` re-executes itself under **sudo**
> automatically so it can read root-owned config (`/etc/ssh/sshd_config`) and
> apply fixes: the prompt you see is sudo's own. To instead show the graceful
> non-root behaviour, run `HOSTVEIL_NO_SUDO=1 hostveil scan`: the root-owned
> domains are skipped with a clear message and the score is renormalized;
> itself a nice thing to demo.

**Web dashboard**: port 8787 is forwarded to the host, so while
`./run.sh web` is running, open **<http://localhost:8787>** in your browser.

Hostveil is built from the synced repo at `/hostveil`, so it reflects your
local source **as of the last sync and rebuild**. After editing code on the
host:

```bash
./run.sh build     # re-sync + rebuild in one shot
```

`./run.sh up` does this for you on every boot. That matters because the build
lives in `provision.sh`, and **`vagrant up` only runs provisioners the first
time a VM is created**, so a plain `vagrant up` on an existing VM re-syncs
your source but leaves the *original* binary in place. You then test stale code
with no warning: the giveaway is `==> default: Machine already provisioned.`
in the `up` output.

Raw Vagrant equivalents, if you prefer them:

```bash
vagrant rsync && vagrant provision     # sync, then re-provision + rebuild
vagrant rsync && vagrant ssh -c 'cd /hostveil && sudo /usr/local/go/bin/go build -o /usr/local/bin/hostveil ./cmd/hostveil'
```

(Or run `vagrant rsync-auto` in a separate terminal to sync on every save.)

---

## AI explanations (optional)

`hostveil explain <id> --ai` and the dashboard's *Explain with AI* button are
optional and advisory: see [docs/ai.html](https://hostveil.seolcu.com/docs/ai)
for the full contract. Nothing here is on by default, and `./run.sh scan` /
`./run.sh web` work exactly as above with none of this set.

Hostveil itself has no config file, but `run.sh` has its own, purely as a
convenience so you don't have to `export` the same key every session: copy
`demo/.env.example` to `demo/.env` and fill in a provider's block. `run.sh`
sources it automatically (if present) and forwards what it sets onto its
`vagrant ssh` command for `scan` and `web`:

```bash
cp demo/.env.example demo/.env
$EDITOR demo/.env      # uncomment one provider block, fill in the key
./run.sh web
```

`demo/.env` is gitignored: it never reaches a commit, only `.env.example`
does. If you'd rather not have a file at all, exporting the same variables on
the host before running `scan`/`web`/`shell` works identically:

```bash
export HOSTVEIL_AI_PROVIDER=openai
export HOSTVEIL_OPENAI_BASE_URL=https://opencode.ai/zen/v1   # or .../zen/go/v1 for OpenCode Go
export HOSTVEIL_OPENAI_API_KEY=...
export HOSTVEIL_OPENAI_MODEL=...   # a model ID from that provider's own catalog
./run.sh web
```

Any OpenAI-compatible vendor works the same way: only the base URL, key and
model change. `HOSTVEIL_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=...` or a
local `HOSTVEIL_AI_PROVIDER=ollama` (the default) work identically, from
either `.env` or an export; `run.sh` forwards whichever of those end up set
and leaves the rest alone.

`./run.sh shell` does not source `.env` for you inside the VM (the guest's
own shell has no view of it) so `export` the same variables by hand there
before running `hostveil explain ... --ai` directly.

---

## Presenting: `ssh homelab`

`run.sh` is for working on Hostveil. To *show* it, make the VM look like what
it stands for, a home server you SSH into, and forget there is a VM (Linux +
libvirt):

```bash
./run.sh up && ./homelab setup     # once, with internet: warms Trivy, saves a memory snapshot
```

From then on the demo is what a self-hoster actually types:

```bash
ssh homelab          # starts the VM by itself if it is off
hostveil             # TUI
hostveil web         # click the URL it prints: 8787 is already tunnelled by `ssh homelab`
```

Between visitors, on the laptop: `homelab reset` reverts to the clean
vulnerable server in a few seconds (a memory snapshot, so nothing boots and the
stacks come back running). `homelab off` shuts it down. Vagrant is not used
after setup. `setup` also pins Trivy's vulnerability DB inside the VM so CVE
scans work with no internet.

## Suggested demo script (5 minutes)

1. **Scan**: `hostveil scan`
   Score is low; findings are grouped by severity with plain-language
   descriptions across Docker/Compose, SSH, firewall, auto-updates, and CVEs.
2. **Explain one**: `hostveil explain compose.ds018 --service redis`
   ("a database exposed to the whole internet").
3. **Fix with a preview**: `hostveil fix ssh.rootlogin`
   Shows the exact diff, backs up the file, applies it. Then
   `hostveil rollback <id>` restores it byte-for-byte.
4. **Fix everything safe**: `hostveil fix --all`, then say yes to
   recreating the containers. Watch the score jump.
5. **Re-scan**: `hostveil scan` shows what's now *resolved*.
6. **Web**: `hostveil web` inside `ssh homelab`, open the link it prints,
   and do the same from the browser.

Judges can poke around and see it's a real server: `docker ps`,
`systemctl status ssh`, `sudo ufw status`.

---

## Reset between demo runs

Take a snapshot once the server is up, then restore it to get a pristine
vulnerable server every time:

```bash
./run.sh snapshot     # once, after `./run.sh up`: saves the "clean" baseline
# ... demo, apply fixes ...
./run.sh reset        # back to the original vulnerable state + stacks restarted
```

Tear it down completely with `./run.sh destroy`.

---

## Troubleshooting

**`Name demo_default of domain about to create is already taken`.** A libvirt
domain exists that Vagrant has no record of: the leftovers of a creation that
did not finish. Vagrant's message reads as a name collision, but renaming
nothing will help; the domain is unreachable anyway, because an unfinished VM
never had an SSH key inserted. Remove it and start again:

```bash
virsh -c qemu:///system destroy demo_default        # only if it is still running
virsh -c qemu:///system undefine demo_default --remove-all-storage
```

`./run.sh up` checks for this and says so before Vagrant gets the chance. The
usual way to get one is the `qemu:///session` trap described above.

**The VM has no internet during `vagrant up` (Linux + libvirt + Docker on the host).**
If the host also runs Docker, Docker sets the kernel's `FORWARD` policy to
DROP, which blocks the libvirt VM's NAT traffic: provisioning dies at the
Docker install with `curl: (28) ... Timeout was reached`. The giveaway is
that the VM looks half-connected: DNS resolves and the gateway pings,
because both are the bridge itself, and everything that has to be *forwarded*
times out. Allow that bridge to forward:

```bash
br=$(virsh -c qemu:///system net-dumpxml vagrant-libvirt |
  sed -n "s/.*<bridge name='\([^']*\)'.*/\1/p")
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
  -i "$br" -j ACCEPT
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
  -o "$br" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo firewall-cmd --reload
```

Then `vagrant provision` to finish the run that failed.

Three things that are easy to get wrong here, and each of them costs you
another five-minute timeout:

- **It is not `virbr0`.** That is the `default` libvirt network, which this
  demo does not use: the VM is on `vagrant-libvirt`, usually `virbr1`. Hence
  reading the name out of the network.
- **`--permanent` is not optional in practice.** Runtime rules are gone after
  a reboot, and Docker sets the policy again the moment it starts, so the
  problem comes back looking brand new.
- **Inbound is replies only.** This VM publishes an *unauthenticated Docker
  API* on 2375, which `dockerd.api-unauthenticated` detects, so
  nothing should be able to open a connection *to* it. Outbound plus
  `RELATED,ESTABLISHED` is all the provisioning needs. `vagrant ssh` and the
  forwarded 8787 are unaffected either way: the host sits on that bridge
  directly, so its own traffic never passes through `FORWARD`.

No masquerade rule is needed. The `vagrant-libvirt` network is
`forward mode='nat'`, so libvirt already masquerades for it; the only thing
in the way is the forwarding policy. And none of this affects teammates on
VirtualBox (macOS/Windows), whose NAT is independent of the host firewall.

## What's vulnerable

The host is set up the way a careful install leaves it, and then changed the
way a hurried one does. Nearly everything the scan finds is something
`hostveil fix --all` fixes, so the demo shows the whole loop: a low score,
one button, the services recreated, a high score.

| Domain | Seeded problem | Example finding |
|---|---|---|
| Docker/Compose | Postgres and Redis published on `0.0.0.0`, Adminer (an admin panel) and Gitea on every interface, no `no-new-privileges`, no restart policy | `compose.ds018`, `ds019`, `dr002`, `ds006`, `ds008` |
| SSH | root login allowed (root's password is locked, so the fix is Auto), empty passwords, weak `MaxAuthTries`, X11 forwarding, no keepalive limits | `ssh.rootlogin`, `ssh.emptypasswords`, … |
| Firewall | `ufw` installed but inactive: the one Review fix to show by hand | `firewall.inactive` |
| Auto-updates | unattended-upgrades disabled, sysstat off | `updates.disabled`, `updates.sysstat-disabled` |
| File permissions | `/etc/shadow` made world-readable | `fileperms.shadow` |
| AI agents | an OpenClaw config with the control UI's auth checks off, elevated commands on and private-network browsing allowed; world-readable credentials | `agent.control-ui-insecure`, `agent.elevated-enabled`, `agent.secret-exposed`, … |
| Kernel | `ptrace_scope` and `perf_event_paranoid` relaxed in `/etc/sysctl.d/98-local.conf`, and the stock values Ubuntu leaves unhardened; rare protocol modules loadable | `sysctl.ptrace-scope`, `sysctl.module-dccp`, … |
| Docker daemon | live-restore off (a stock default; Docker applies the fix on a reload) | `dockerd.live-restore` |

What is left after the safe fixes, and why:

- `firewall.inactive`: Review, to apply by hand during the demo.
- `ssh.allowtcpforwarding`: `ssh homelab` tunnels the dashboard through it.
- `accounts.sudo-nopasswd`: Vagrant needs it.
- `dockerd.userns-remap`: it moves every image into new storage.
- `cve.*`: the Ubuntu packages' unfixed vulnerabilities, and whatever the
  current images carry. The stacks build each image from its release with
  the Alpine packages upgraded (`stacks/*/*.Dockerfile`), so a fresh build
  has as few as the vendors allow.

The stacks live in `stacks/`, the SSH snippet and the agent configs in
`seed/`, and the whole build lives in `Vagrantfile` + `provision.sh`.

> **On the agent fixtures**: OpenClaw and Hermes are not *installed*;
> neither is packaged for apt, and neither ships a daemon the demo could
> accurately run. `provision.sh` seeds their configuration and file layout
> instead, which is what the agent domain inspects anyway.
