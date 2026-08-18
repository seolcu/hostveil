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
AGENTS.md            architecture + invariants, written for AI coding agents
cmd/hostveil/        entry point + subcommand wiring
cmd/sitegen/         static-site generator for site/ (templates + content + pages.json)
internal/
  core/              the shared engine — the only thing the UIs call
  check/             detection domains (compose, ssh, firewall, updates, cve,
                     ports, accounts, fileperms, agent, sysctl, dockerd)
  fix/ compose/ history/   fix registry, YAML editing, backup/rollback
  model/ platform/   pure value types; the OS/command seam
  clirender/         the CLI's report rendering
  ui/{theme,tui,web}/  thin UIs over the engine, and the one palette registry
demo/                the reproducible vulnerable-server VM (Vagrant)
scripts/measure/     the harness that measures hostveil with other tools
site/                the marketing site (static, generated — see below)
docs/                these docs, and docs/measurements/ — committed results
```

`AGENTS.md` is worth reading even if you never use a coding agent: it is the
shortest description of the architectural rules that span multiple files — the
one-engine/thin-UI split and the tests that enforce it, the seams that keep
checkers and fixes unit-testable, and the scoring invariants. Claude Code
reaches it through a one-line `CLAUDE.md` that imports it; OpenCode and Codex
read it directly.

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

Metadata in `pages.json` (titles, descriptions, nav labels) is **plain text** —
the generator HTML-escapes it at render time, so write `Fixing & rollback`, not
`Fixing &amp; rollback`. Content fragments under `content/` are raw HTML.

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
bring up on any machine. hostveil is built from your working tree, which is
rsync-synced *into* the VM, so a freshly booted VM reflects your current code.
(After editing code, re-sync before rebuilding — the repo syncs on `up`/`reload`
but not on `provision`; see [demo/README.md](../demo/README.md).)

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

### Checking a UI change without sitting at the keyboard

A screenshot is the only honest way to review a colour, a layout, or anything
that reflows. All three of these run against the demo VM, so nothing is aimed
at your own machine:

```bash
# TUI — drive the real thing and read back what it drew
vagrant ssh -c 'tmux -f /dev/null new-session -d -x 100 -y 34 "sudo hostveil tui"'
vagrant ssh -c 'tmux send-keys -t 0 t; sleep 1; tmux capture-pane -p -t 0'   # -e keeps the colour codes

# Web — a throwaway profile, or Firefox hangs waiting on the one you have open
firefox --headless --no-remote --profile "$(mktemp -d)" \
        --window-size=1400,900 --screenshot out.png http://localhost:8787/

# What actually reaches the terminal, escape sequence by escape sequence.
# stty is not optional: `vagrant ssh -c` has no terminal for script(1) to copy
# a size from, so the pty it builds is 0x0 and bubbletea draws nothing into it
# — you get the altscreen and cursor setup, not one glyph. Feed it a quit key,
# or it runs until the timeout.
vagrant ssh -c '(sleep 90; printf q) | script -qfc "stty rows 45 cols 200; sudo -E env TERM=xterm-256color hostveil" /tmp/raw.log'
vagrant ssh -c "grep -o '38;5;[0-9]*' /tmp/raw.log | sort | uniq -c | sort -rn"
```

Use `tmux capture-pane` when you want to *read* the screen and the raw log
when you want to know which palette entry drew something — the palettes are
24-bit hex and SSH does not forward `COLORTERM`, so what a remote session
actually receives is the quantised 256-colour index and not the hex
(`internal/ui/tui/quantize_test.go` holds every theme to that).

### Capturing the whole interface

All three surfaces draw the same written-down host — `uitest.PublishedReport` —
so a set of captures is a set of pictures of one machine rather than of three
machines that happened to be to hand. Every hook is a test that skips unless its
environment variable is set, so none of them runs in CI.

```bash
# TUI — one .ans per screen into a directory (a file path gets the site frame)
HOSTVEIL_SNAPSHOT=/tmp/frames go test ./internal/ui/tui -run TestSnapshotDump

# CLI — the four shapes `hostveil scan` prints
HOSTVEIL_SNAPSHOT=/tmp/cli go test ./internal/clirender -run TestSnapshotDump

# Dashboard — serves the fixture, prints a URL, exits after 45s
HOSTVEIL_SCREENSHOT_ADDR=127.0.0.1:8788 go test ./internal/ui/web -run TestScreenshotServe -v
```

A palette and an arrangement are the two things only a picture can review, and
each hook was reachable in exactly one of each — so reviewing the other five of
either meant clicking through a live dashboard on some host, which is the drift
these hooks were written to remove. Both are selectable, and an unknown ID is a
hard failure rather than a silent fall back to the default: a typo would
otherwise produce a full set of frames named after the palette asked for and
drawn in another.

```bash
HOSTVEIL_SNAPSHOT_THEME=nord    HOSTVEIL_SNAPSHOT_LAYOUT=lanes    …  # TUI
HOSTVEIL_SCREENSHOT_THEME=nord  HOSTVEIL_SCREENSHOT_LAYOUT=lanes  …  # dashboard
```

Rendering a `.ans` to PNG is `scripts/ansi2png.py`. A capture of a non-default
palette needs its ground and ink passed in, since a terminal capture cannot
carry them and the renderer assumes One Dark's:

| theme | `HOSTVEIL_ANSI2PNG_BG` | `HOSTVEIL_ANSI2PNG_FG` |
| --- | --- | --- |
| `onedark` (default) | `#282c34` | `#c8ccd4` |
| `gruvbox` | `#1d2021` | `#ebdbb2` |
| `nord` | `#22262e` | `#eceff4` |
| `catppuccin` | `#1e1e2e` | `#cdd6f4` |
| `tokyonight` | `#1a1b26` | `#c0caf5` |

### The two screenshots on the website

`site/assets/tui.png` and `site/assets/web.png` are the only claims the site
makes that a reader believes on sight, and they were the only ones no test
checked. `tui.png` spent two releases showing a four-level severity scale that
had already been replaced by three. Both are covered now, differently, because
only one of them can be re-rendered from Go.

**`tui.png` is regenerated, not photographed.** The frame it is made from is
committed at `internal/ui/tui/testdata/site-frame.ans`, and
`TestSiteFrameIsCurrent` re-renders it on every test run and fails with the
first differing line when the interface moves. To update both after reviewing
that diff:

```bash
HOSTVEIL_SNAPSHOT="$PWD/internal/ui/tui/testdata/site-frame.ans" \
  go test ./internal/ui/tui -run TestSnapshotDump
python3 scripts/ansi2png.py internal/ui/tui/testdata/site-frame.ans site/assets/tui.png
```

`ansi2png.py` needs DejaVu Sans Mono, which is the face the published image is
set in — `apt install fonts-dejavu-core`, `dnf install dejavu-sans-mono-fonts`.
It says so if the font is missing. `HOSTVEIL_ANSI2PNG_BG`/`_FG` override the
ground and default ink, which a capture of a non-default theme needs: a
terminal capture cannot carry them, so the renderer assumes One Dark's `Ink`
and `Bone`.

**`web.png` is photographed, so its *inputs* are pinned instead.** There is no
headless browser in the test suite, so `TestDashboardScreenshotStampIsCurrent`
hashes everything that decides what that page looks like — the generated
`/model.js`, `/themes.css` and `/theme.js`, plus the three embedded assets —
against `internal/ui/web/testdata/web-shot.stamp`, and names which one moved.

Re-shooting it does not need the demo VM. `TestScreenshotServe` puts the real
dashboard — every route, asset and generated stylesheet from `Server.Handler`,
on the default theme and arrangement — in front of the same fixture the
terminal frame draws, so both published screenshots are pictures of one host:

```bash
HOSTVEIL_SCREENSHOT_ADDR=127.0.0.1:8788 HOSTVEIL_SCREENSHOT_SECONDS=120 \
  go test ./internal/ui/web -run TestScreenshotServe -v      # prints a URL
firefox --headless --no-remote --profile "$(mktemp -d)" \
        --window-size=1500,760 --screenshot /tmp/web.png "<the URL>"
cp /tmp/web.png site/assets/web.png
```

Shoot into `/tmp` and copy: Firefox's `--screenshot` fails silently when the
output path contains non-ASCII characters, which a checkout under a path like
`~/프로젝트/` has. Then:

```bash
HOSTVEIL_UPDATE_STAMP=1 go test ./internal/ui/web -run TestDashboardScreenshotStampIsCurrent
```

Neither check can tell you the picture is *good*. What they guarantee is that
nobody ships an interface change without being told the picture is now a
picture of something else.

### Measuring hostveil with tools that are not hostveil

The end-to-end job checks that the score improves after `fix --all`. That
only shows hostveil is self-consistent: the same code decides what a finding
is, what fixing it means, and what the number should be afterwards.
`scripts/measure/` closes that circle with auditors that have never heard of
it — Lynis, docker-bench-security, and a TCP connect scan from a container
off the host — run before the fixes, after them, and again after every fix
has been rolled back.

The auditors are installed by `scripts/measure/seed.sh`, which is what puts a
throwaway host into the profile the published figures were taken on. The demo
VM is built by `demo/provision.sh` instead and has neither Lynis nor
docker-bench, so the harness there measures hostveil and the port scan and
records the other two as missing — a full run wants a seeded host.

```bash
# On the demo VM, or any host you are willing to have edited.
vagrant ssh -c 'sudo /hostveil/scripts/measure/run.sh -c -p seeded /tmp/out.json'

# The control group: hardened from the CIS Benchmarks, without hostveil.
vagrant ssh -c 'sudo /hostveil/scripts/measure/control.sh'
vagrant ssh -c 'sudo /hostveil/scripts/measure/run.sh -p control /tmp/control.json'
```

Results are committed under `docs/measurements/` and published on the
[Measured results](https://hostveil.seolcu.com/docs/measurements) page, whose figures
are pinned against the committed JSON by `internal/docs/measurements_test.go`.
A stale number on the page is a test failure, not a reading error.

Pass `-c` and the run exits non-zero on the only two claims in its output
that are promises rather than observations: that rolling every fix back
restored each changed file byte for byte, and that hostveil's own score moved
at all. Everything else is recorded and nothing else is asserted — those
numbers move for reasons no diff is responsible for, and a check that turns
red for a Lynis release is a check somebody disables, taking the two real
ones with it.

### Provider setup by platform

**Linux — libvirt/KVM** (fastest, native):

```bash
# Debian/Ubuntu: apt install vagrant vagrant-libvirt qemu-kvm libvirt-daemon-system
# Fedora/RHEL:   dnf install vagrant vagrant-libvirt qemu-kvm libvirt virt-install
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"     # then log out/in
```

Use `demo/run.sh`, or export `LIBVIRT_DEFAULT_URI=qemu:///system` before
raw `vagrant`. An unprivileged libvirt client resolves to `qemu:///session`,
which has no management network, so the VM boots and never gets an address —
Vagrant reports *"not yet ready for SSH"* minutes later and leaves a domain
behind that makes the next attempt fail with *"already taken"*. `run.sh`
sets the URI and checks for that leftover; raw `vagrant` does neither.

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
- **Ollama** (local LLM) powers the opt-in `hostveil explain --ai` by
  default; without it, explanations are deterministic. Never required —
  `HOSTVEIL_AI_PROVIDER=anthropic` or `openai` uses an external API instead,
  useful when the dev machine can't run a local model well.
