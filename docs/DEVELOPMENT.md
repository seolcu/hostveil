# Developing hostveil

How to set up a machine to build, test, and run hostveil. For end-user
install instructions see the [README](../README.md); for the demo VM in
depth see [demo/README.md](../demo/README.md).

## Prerequisites

- **Go** — the version in [`go.mod`](../go.mod) (currently 1.26.x) or newer.
  Install from your package manager or <https://go.dev/dl/>.
- **git**.
- **(Optional) the demo VM** — [Vagrant](https://developer.hashicorp.com/vagrant/install)
  plus a provider (libvirt on Linux, VirtualBox on macOS/Windows). Needed
  only to *run* hostveil against a realistic host; not needed to build/test.

## Build and test

```bash
git clone https://github.com/seolcu/hostveil.git
cd hostveil
go build ./cmd/hostveil     # produces ./hostveil
go test ./...               # unit + fuzz + property tests
```

Before sending a change, the same checks CI runs:

```bash
go build ./...
go vet ./...
gofmt -l .                  # must print nothing
go mod tidy                 # must leave go.mod/go.sum unchanged
go test -race ./...
```

> **hostveil is a Linux tool.** It reads host configuration
> (`/etc/ssh/sshd_config`), inspects Docker Compose projects, and shells out
> to `ufw`/`firewalld`/`trivy`. It **builds and its tests pass on any OS**
> (macOS, Windows), but running the binary meaningfully requires Linux with
> those tools present — use the demo VM below rather than running it against
> your own machine.

## Repository layout

```
cmd/hostveil/        entry point + subcommand wiring
cmd/sitegen/         static-site generator for site/ (templates + content + pages.json)
internal/
  core/              the shared engine — the only thing the UIs call
  check/             detection domains (compose, ssh, firewall, updates, cve)
  fix/ compose/ history/   fix registry, YAML editing, backup/rollback
  model/ platform/   pure value types; the OS/command seam
  ui/{cli,tui,web}/  thin UIs over the engine
demo/                the reproducible vulnerable-server VM (Vagrant)
site/                the marketing site (static, generated — see below)
docs/                these docs
```

## Editing the website

`site/` is a static site (landing page + docs, mirrored under `site/ko/`), but
its HTML is **generated** — don't hand-edit `site/**/*.html`. The single source
of truth lives in `cmd/sitegen/`:

```
cmd/sitegen/
  pages.json         per-page/per-language metadata; drives the sidebar + head
  templates/*.tmpl   shared head, nav, sidebar, footer, and the two layouts
  content/{en,ko}/   per-page body fragments (the actual prose)
  main.go            resolves each page's chrome/URLs and renders it
```

Edit a fragment, template, or `pages.json`, then regenerate and commit the
result:

```bash
go run ./cmd/sitegen      # writes into site/
git diff site/            # review, then commit the regenerated HTML
```

CSS/JS (`site/styles.css`, `docs.css`, `script.js`, `docs.js`,
`lang-suggest.js`) and `site/assets/` are shared by every page and are *not*
generated — edit them directly. CI runs the generator and fails if `site/`
drifts from the source, so always commit the regenerated output.

Architectural rule: UIs depend only on `core` (an import-lint test enforces
that `ui/*` never imports `fix`/`history`/`check`/`compose`). Adding a
detection domain means writing one package under `internal/check/` that
implements the `Checker` interface and registering it.

## Running it for real: the demo VM

`demo/` is a code-defined, deliberately vulnerable Ubuntu server you can
bring up on any machine. hostveil is built from your working tree *inside*
the VM, so it always reflects your current code.

```bash
cd demo
./run.sh up        # boot + provision + start the vulnerable stacks
./run.sh scan      # run hostveil against the server
./run.sh web       # dashboard at http://localhost:8787
./run.sh shell     # a shell on the server (then: hostveil ...)
./run.sh halt      # shut it down — nothing keeps running
```

(`run.sh` is a convenience wrapper around `vagrant`; on Windows without a
bash shell, use the raw `vagrant up` / `vagrant ssh` / `vagrant snapshot`
commands instead.) The full walkthrough, demo script, and reset workflow
live in [demo/README.md](../demo/README.md).

### Provider setup by platform

**Linux — libvirt/KVM** (fastest, native):

```bash
# Debian/Ubuntu: apt install vagrant vagrant-libvirt qemu-kvm libvirt-daemon-system
# Fedora/RHEL:   dnf install vagrant vagrant-libvirt qemu-kvm libvirt virt-install
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"     # then log out/in
```

If the host also runs **Docker**, Docker sets the kernel `FORWARD` policy to
DROP, which blocks the VM's outbound network (apt/curl time out during
provisioning). Allow the libvirt bridge to forward + masquerade — see the
Troubleshooting section of [demo/README.md](../demo/README.md) for the exact
`firewall-cmd` commands. Applying them **before** the first `vagrant up`
avoids the issue cleanly.

**macOS / Windows — VirtualBox** (cross-platform):

1. Install [Vagrant](https://developer.hashicorp.com/vagrant/install) and
   [VirtualBox](https://www.virtualbox.org/wiki/Downloads).
2. `cd demo && vagrant up` — the provider is selected automatically.

- **Windows:** VirtualBox conflicts with Hyper-V/WSL2; either disable Hyper-V
  or use a Hyper-V-based provider. No host-firewall tweaks are needed
  (VirtualBox NAT is independent of the host firewall).
- **Apple Silicon (M-series):** amd64 boxes don't run under VirtualBox; use
  an arm64 Ubuntu box with a compatible provider (e.g. UTM/qemu). The demo's
  `provision.sh` already selects the Go build for the VM's architecture.

## Optional tools

- **Trivy** enables image CVE scanning; hostveil skips that domain cleanly
  when it's absent. The demo VM installs it automatically.
- **Ollama** (local LLM) powers the opt-in `hostveil explain --ai`; without
  it, explanations are deterministic. Never required.
