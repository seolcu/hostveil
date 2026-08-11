# hostveil demo — a vulnerable home server in one command

This directory is a **reproducible, code-defined test/demo environment** for
hostveil: a real Ubuntu 24.04 server, deliberately misconfigured the way a
non-expert self-hoster's box would be, running inside a VM.

It exists so you can try hostveil (and demo it) **without touching a real
device**, on any laptop, and so teammates get the exact same environment
from a `git clone`.

```
cd demo
./run.sh up           # boots + provisions the vulnerable server (first run: a few minutes)
./run.sh shell        # you're now on the "home server"
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
3. `vagrant plugin install vagrant-disksize`

That's it — the same `Vagrantfile` picks libvirt or VirtualBox automatically.

> **On the disk.** The box ships 8.7GB and this demo does not fit: the seven
> outdated images are 3.8GB and Trivy's vulnerability DB is another 1.2GB. The
> `Vagrantfile` asks for 24GB, which is sparse and costs what it uses. libvirt
> does this on its own; VirtualBox needs the plugin above, and without it the
> demo still comes up but the CVE domain runs out of room — Trivy unpacks an
> image to scan it, so the two 1.32GB images cannot be scanned at all, and a
> vulnerability score that skipped the heaviest images is *better* than the
> truth. hostveil says "partial" when this happens; the number beside it is
> still wrong.
>
> An existing VM keeps the disk it was built with. `./run.sh destroy` then
> `./run.sh up` to pick up the new size.

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
./run.sh up        # boot the VM + rebuild hostveil + start the stacks (first run downloads the box + images)
./run.sh build     # re-sync the repo and rebuild hostveil in the VM (after editing code)
./run.sh scan      # scored report across all domains
./run.sh web       # dashboard at http://localhost:8787 (Ctrl-C to stop)
./run.sh shell     # a shell on the demo server — then e.g. `hostveil`
./run.sh halt      # shut the VM down; nothing keeps running
```

Prefer raw Vagrant? `vagrant up` / `vagrant ssh` work too (run
`./run.sh up` once after a boot to start the stacks — they intentionally
have no restart policy, so they don't come back on their own). **On Linux,
export `LIBVIRT_DEFAULT_URI=qemu:///system` first.** An unprivileged libvirt
client resolves to `qemu:///session`, which has no management network: the
VM boots, never gets an address, and Vagrant gives up minutes later with
*"not yet ready for SSH"*. `run.sh` sets it for you; raw `vagrant` does not.

> Inside the VM, plain `hostveil` re-executes itself under **sudo**
> automatically so it can read root-owned config (`/etc/ssh/sshd_config`) and
> apply fixes — the prompt you see is sudo's own. To instead show the graceful
> non-root behaviour, run `HOSTVEIL_NO_SUDO=1 hostveil scan`: the root-owned
> domains are skipped with a clear message and the score is renormalized —
> itself a nice thing to demo.

**Web dashboard**: port 8787 is forwarded to the host, so while
`./run.sh web` is running, open **<http://localhost:8787>** in your browser.

hostveil is built from the synced repo at `/hostveil`, so it reflects your
local source **as of the last sync and rebuild**. After editing code on the
host:

```bash
./run.sh build     # re-sync + rebuild in one shot
```

`./run.sh up` does this for you on every boot. That matters because the build
lives in `provision.sh`, and **`vagrant up` only runs provisioners the first
time a VM is created** — so a plain `vagrant up` on an existing VM re-syncs
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

**`Name demo_default of domain about to create is already taken`.** A libvirt
domain exists that Vagrant has no record of — the leftovers of a creation that
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
DROP, which blocks the libvirt VM's NAT traffic — provisioning dies at the
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
  demo does not use — the VM is on `vagrant-libvirt`, usually `virbr1`. Hence
  reading the name out of the network rather than typing it.
- **`--permanent` is not optional in practice.** Runtime rules are gone after
  a reboot, and Docker sets the policy again the moment it starts, so the
  problem comes back looking brand new.
- **Inbound is replies only.** This VM publishes an *unauthenticated Docker
  API* on 2375 — that is the point of `dockerd.api-unauthenticated` — so
  nothing should be able to open a connection *to* it. Outbound plus
  `RELATED,ESTABLISHED` is all the provisioning needs. `vagrant ssh` and the
  forwarded 8787 are unaffected either way: the host sits on that bridge
  directly, so its own traffic never passes through `FORWARD`.

No masquerade rule is needed. The `vagrant-libvirt` network is
`forward mode='nat'`, so libvirt already masquerades for it; the only thing
in the way is the forwarding policy. And none of this affects teammates on
VirtualBox (macOS/Windows), whose NAT is independent of the host firewall.

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
| AI agents | an OpenClaw gateway on the LAN with auth off, unapproved shell exec, sandbox off; world-readable Hermes API keys | `agent.auth-disabled`, `agent.gateway-exposed`, `agent.secret-exposed`, … |
| Docker daemon | the API published on `0.0.0.0:2375` with no TLS, a `0666` docker socket, and a `nologin` CI account in the docker group | `dockerd.api-unauthenticated`, `dockerd.socket-world-writable`, `dockerd.group-members` |

The stacks live in `stacks/`, the weak SSH snippet and the agent configs in
`seed/`, and the whole build lives in `Vagrantfile` + `provision.sh`.

> **On the Docker daemon**: this one is not a fixture, it is the real thing.
> `dockerd.api-unauthenticated` means anyone who can reach port 2375 on this
> VM is root on it — no password, one HTTP request. That is safe here only
> because the `Vagrantfile` NATs the VM and forwards nothing but 8787; if you
> add a forwarded port for 2375, you have published root on your laptop's
> network. The three daemon *defaults* (`no-new-privileges`, `userns-remap`,
> `live-restore`) need no seeding at all — they are off on a stock install,
> which is the whole point of those rules. `dockerd.api-tls-unverified` is
> the one finding the demo does not show, because it needs a server keypair;
> the unit tests cover it instead.

> **On the agent fixtures**: unlike everything else here, OpenClaw and Hermes
> are not actually *installed* — neither is packaged for apt, and neither
> ships a daemon the demo could honestly run. `provision.sh` seeds their
> configuration and file layout instead, which is what the agent domain
> inspects anyway. The one part this cannot show is the listener
> cross-check. The finding is **High** either way — the firewall and the
> listener change how confident it is, not how urgent — but with nothing
> bound to the gateway port its evidence says the binding came from the
> config rather than from an observed socket. Start something on the port to
> see the other case:
>
> ```bash
> python3 -m http.server 18789 --bind 0.0.0.0 &
> hostveil scan          # still High; basis config → config+listener
> ```
