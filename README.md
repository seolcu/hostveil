# Hostveil

**English** · [한국어](README.ko.md)

**Hostveil finds the security mistakes on your self-hosted Linux server, explains them in plain language, and fixes them safely.**
One binary, no config file, no cloud account. Every fix is previewed,
backed up, and reversible with one command.

[![CI](https://github.com/seolcu/hostveil/actions/workflows/ci.yml/badge.svg)](https://github.com/seolcu/hostveil/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/seolcu/hostveil)](https://github.com/seolcu/hostveil/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/seolcu/hostveil)](go.mod)
[![License: GPL-3.0](https://img.shields.io/github/license/seolcu/hostveil)](LICENSE)

[Website](https://hostveil.seolcu.com/) · [Docs](https://hostveil.seolcu.com/docs/) · [Changelog](CHANGELOG.md) · [Latest release](https://github.com/seolcu/hostveil/releases/latest)

> Winner of the Grand Prize (Development) at the 2026-1 Ajou University SoftCon.

<p align="center">
  <img src="site/assets/web.png" width="900"
       alt="Hostveil's web dashboard: a 0–100 security score, per-domain meters, and findings grouped by severity with one-click safe fixes">
</p>

---

Most self-hosted boxes — Jellyfin, Nextcloud, a game server, a local LLM, a
self-hosted AI agent like OpenClaw or Hermes Agent — run on whatever defaults
the install left behind, and one bad default is
enough to lose the box. Point Hostveil at one and it checks the places that
matter most, gives you a single 0–100 score, describes each problem without
jargon, and offers to fix it: preview first, backup, then apply, with one
command to undo it.

## Does it actually work?

Hostveil's own score going up after Hostveil's own fixes proves nothing — the
same code decides what a finding is and what the score should be afterward.
So this repository ships a harness that measures a seeded, ordinary
self-hosted host with tools that have never heard of Hostveil: Lynis,
Docker's CIS benchmark, a TCP scan from off the host, and the kernel's own
list of listening sockets. The seed is Nextcloud with PostgreSQL, Jellyfin
with Redis, Portainer with Watchtower, every port on `0.0.0.0`, root SSH
login allowed, no firewall, no automatic updates.

| Measured by | Before | After `fix --all --review` |
| --- | --- | --- |
| **Ports answering from off the host** | 7 | **1** |
| CIS Docker Benchmark (pass / warn) | 17 / 15 | **20 / 12** |
| Lynis hardening index | 57 | **60** |
| Hostveil's SSH domain | 18/100 | **100/100** |
| Hostveil score | 29 | **51** |

The host that produces those numbers is `scripts/measure/seed.sh`, in this
repository — the run above is one you can reproduce, not one you have to take
on trust.

Rollback restored every file the fixes changed, byte for byte: 8 of 8, across
48 checkpoints. 7 of the 18 reviewed fixes leave nothing to roll back at all —
they are not file edits — and Hostveil marks each of those `[not reversible]`
in its own history rather than implying the undo is total.

What did *not* move matters too. The container axis stays near 0 by design: a
Docker socket mounted into Portainer, host networking, secrets in the
environment — Manual, not missed. And Lynis's own index moved 57 → 60 while
Two of Lynis's 4 warnings never cleared, because the index scores tests it
does not print — a harness that reported only the index would have looked
better and said less.

Full numbers, the method, and everything that did not move are on the
[Measured results](https://hostveil.seolcu.com/docs/measurements) page. Run
it yourself with `scripts/measure/run.sh -c`, on a container or a throwaway
VM rather than your own machine.

## How it compares

Most server-hardening tools are auditors — a report, and the fixing left to
you. Hostveil closes that loop and applies the fix itself.

- **[Lynis](https://github.com/CISOfy/lynis)** is a thorough, expert-oriented
  host auditor. It prints a long list of suggestions but doesn't apply them,
  and reading the output assumes you already know which ones matter.
- **[docker-bench-security](https://github.com/docker/docker-bench-security)**
  checks a Docker host against the CIS benchmark. It's container-only, and it
  reports rather than fixes.
- **[Trivy](https://github.com/aquasecurity/trivy)** scans images and
  filesystems for known CVEs and misconfigurations. It's excellent at that one
  job, and Hostveil actually *runs* Trivy for its CVE domain, but it doesn't
  look at your SSH config, firewall or accounts.

Hostveil's angle is to merge the host, your containers and image CVEs into a
single 0–100 score, explain each finding in plain language, and then apply the
fix, with a preview, a backup and one-command rollback. One binary, and no
report to interpret.

## What it checks

Findings are named after the domain that found them. The prefix in the second
column is what you pass to `hostveil fix` and `hostveil explain`.

| Domain | Findings | What it looks at | Needs |
| --- | --- | --- | --- |
| **Docker / Compose** | `compose.*` | Privileged mode, Docker socket mounts, exposed datastores and admin panels, host networking, unsafe bind mounts, shared PID and IPC namespaces, writable root filesystems, missing no-new-privileges, hardcoded secrets, and more. Your Compose files are audited natively, and so are containers started with a plain `docker run` | Docker |
| **SSH** | `ssh.*` | Root login, password authentication, empty passwords, weak brute-force limits, login grace time, gateway ports, host-based and keyboard-interactive auth, X11 forwarding. Parsed from `sshd_config` directly, following `Include` into `sshd_config.d/`. Reading stops at the first `Match` block and the domain reports partial coverage, because a directive that applies to some connections is not a statement about the host | — |
| **Firewall** | `firewall.*` | Whether ufw, firewalld, nftables or iptables is actually active, and whether published container ports are quietly bypassing it | — |
| **Auto-updates** | `updates.*` | Whether unattended-upgrades (apt) or dnf-automatic (dnf) is enabled | — |
| **Exposed services** | `ports.*` | Host processes listening on a non-loopback address, read from `ss`. This is the natively installed database, admin panel or app that a Compose audit cannot see | `ss` |
| **Accounts** | `accounts.*` | Who can become root, and what stands in their way: non-root accounts carrying root's UID (0), login accounts with an empty password, and accounts a sudo rule lets run anything as root without being asked for one — the rule cloud and VM images ship so the first login works. sudo is asked what each account may actually run, rather than `/etc/sudoers` being re-parsed | root (for `/etc/shadow` and sudo) |
| **File permissions** | `fileperms.*` | Over-permissive modes on `/etc/shadow`, `/etc/passwd`, `/etc/group`, `sshd_config`, and SSH host private keys | — |
| **AI agent runtimes** | `agent.*` | Self-hosted agent runtimes, OpenClaw and Hermes Agent: a gateway reachable off-host, authentication turned off on one that is, unrestricted shell and elevated tools, a disabled sandbox, and loose permissions on the config and the API keys beside it | — |
| **Kernel hardening** | `sysctl.*` | Eight kernel parameters read straight from `/proc/sys`: the quiet knobs that stop a local foothold from becoming root and a spoofed packet from becoming a route. No `sysctl` binary needed | — |
| **Docker daemon** | `dockerd.*` | The daemon underneath your containers. An API served over TCP without TLS client verification is unauthenticated root for anyone who can reach the port; Hostveil also checks for a world-writable socket, who holds the socket's group, and the defaults for no-new-privileges, userns-remap and live-restore | Docker |
| **Service hardening** | `systemd.*` | The units you installed yourself, read as systemd's own *effective* configuration: whether a service can gain privileges through setuid, write to `/usr` and `/etc`, read every user's home directory, or share `/tmp` with the rest of the host. Distribution units are left to the distribution | systemd |
| **Reverse proxy** | `proxy.*` | The thing on 443 that everything else is behind. nginx read from `/etc/nginx`, following `include` into `conf.d` and `sites-enabled`, for deprecated TLS versions and directory listing; Traefik read from your Compose files, for the dashboard served in insecure mode — an unauthenticated page listing every backend address behind the proxy, and the setting nearly every Traefik tutorial tells you to add | — |
| **Image CVEs** *(optional)* | `cve.*` | Known vulnerabilities in the images your Compose services run | Trivy |

If Docker or Trivy is missing, those domains are skipped and the score is
renormalized over the ones that ran, so a partial scan never comes back as a
misleadingly perfect result.

Hostveil can report **174 findings** across those domains, and **120 of them
carry a fix** — 71 Hostveil will apply unattended, 49 only after you have read
the diff. The rest are Manual on purpose, and each one is named in the register
in [`internal/fix/register.go`](internal/fix/register.go) with the reason
Hostveil will not touch it. Manual by decision, never Manual because nobody
looked — a test fails the build on the difference.

## How it's tested

Hostveil runs as root and edits configuration files on servers people depend
on. That is a lot to ask, so this is what stands behind it.

- **There is more test code in this repository than product code.** Not a
  ratio anyone targets — it is what auditing an operating system honestly
  costs, and a test enforces the inequality rather than a number.
- **[`internal/docs/`](internal/docs) fails the build when a published page
  drifts from the code.** Every domain table, every finding ID in a
  screenshot, every figure on the measured-results page — checked against
  what the program actually does.
- **5 fuzz targets run nightly**, five minutes each, over the config editors
  and parsers that rewrite your files.
- **Every pull request drives the real binary end to end** — scan, fix,
  history, rollback, rescan — inside a seeded Debian container.
- **Every release target is cross-compiled on every pull request**, so a break
  appears while it is still a pull request.
- **[`demo/`](demo/README.md) is a Vagrant VM** seeded to be vulnerable, so you
  can watch a hardening tool edit a server before you let it near one of yours.

None of that answers whether the fixes change anything real. That is what the
harness in [`scripts/measure/`](scripts/measure) is for — see the section
above.

## Install

```bash
curl -fsSL https://hostveil.seolcu.com/install.sh | bash
```

Or install a native package from the
[latest release](https://github.com/seolcu/hostveil/releases/latest):

```bash
sudo apt install ./hostveil_<version>_linux_amd64.deb   # or dnf install ./hostveil-<version>.x86_64.rpm
```

Either route puts the same binary at the same path (`/usr/bin/hostveil`).
Docker and `iproute2` are recommended but not required — without them, those
domains report N/A instead of failing the scan. To build it yourself you need
Go 1.26 or later:

```bash
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Trivy is optional, for image CVE scanning. `hostveil update` and
`hostveil uninstall` handle upgrades and removal themselves, however you
installed it. Releases are checksummed and carry a signed build provenance
attestation and an SBOM — see [Installation](https://hostveil.seolcu.com/docs/installation)
for verifying a download before you run it.

## Usage

```bash
hostveil                 # interactive TUI (default on a terminal)
hostveil scan            # print a scored report (add -v for details, --json for JSON)
hostveil fix <id>        # preview, then apply the fix for one finding
hostveil fix --all       # apply every safe (Auto) fix at once
hostveil fix --all --review  # and the Review ones too, after reading what they are
hostveil rollback <id>   # undo a previously applied fix
hostveil history         # list applied fixes and their rollback IDs
hostveil history --scans # the score of every saved scan, oldest first
hostveil explain <id>    # explain a finding (add --ai for a local-LLM second opinion)
hostveil serve           # web dashboard on 127.0.0.1:8787 (open the printed URL)
hostveil update          # update this binary the way it was installed
hostveil uninstall       # remove it, keeping your checkpoints
```

Some checks read root-owned files, and applying a fix needs root, so Hostveil
re-runs itself under `sudo` when it has to — the same password prompt as
`sudo hostveil`. `version` and `help` never prompt. For scripts and CI, set
`HOSTVEIL_NO_SUDO=1`; the root-only domains are skipped with a message saying
so.

### Using it as a CI or cron gate

`hostveil scan` reports what it found in its exit status, so a scheduled check
does not have to parse any output.

| Code | Meaning |
| --- | --- |
| `0` | The scan ran and found nothing High. |
| `1` | At least one unfixed High finding. |
| `3` | A detection domain failed outright, so the scan covered less of the host than it should have. |

```bash
HOSTVEIL_NO_SUDO=1 hostveil scan --json > report.json || echo "action needed"
```

Exit code **3** is worth wiring up: a failed domain contributes no findings,
so without it a blind scan and a healthy host look identical to a consumer
that only reads the exit status. `--sarif` writes SARIF 2.1.0 for GitHub code
scanning and most CI systems, and `--only`/`--skip` narrow a run to some
domains. See [CLI reference](https://hostveil.seolcu.com/docs/cli) for the
full flag set and the SARIF field mapping.

Other commands exit 0 on success, 1 on failure and 2 on a usage error.

### When something looks wrong

`HOSTVEIL_DEBUG=1` traces every command Hostveil runs against the host to
stderr — what ran, how long it took, and whether it failed. Command *output*
is never logged, deliberately: `docker inspect` prints the resolved
environment of every container, and a trace that included it would leak
credentials as a matter of routine.

```bash
HOSTVEIL_DEBUG=1 hostveil scan
```

See [Troubleshooting](https://hostveil.seolcu.com/docs/troubleshooting) for what
Degraded, a declined rollback, an empty history and exit code 3 mean.

## How fixing works

Every finding is classified, so the tool never changes anything blindly:

| Kind | Meaning | Hostveil can apply it |
| --- | --- | --- |
| **Auto-fix** | One clearly correct change. You still see it first. | Yes |
| **Review** | Two or more independent alternatives; you pick one. | Yes |
| **Manual** | Nothing safe to automate, so Hostveil explains what to do instead. | No |
| **Unavailable** | A real problem with no fix in existence yet, such as a CVE with no published patch. | No |

`fix --all` applies only the Auto-fix ones. `fix --all --review` applies the
Review ones too, each through its first alternative.

**Applying a fix is not always a change the host has seen, and the score
knows the difference.** A Compose file is read when the container is
recreated, a systemd drop-in when the unit is reloaded, a sysctl drop-in at
the next boot — until then the finding stays charged and its row is marked
`PEND`, and each fix names the command that puts it in force.

A finding is Auto-fix only when all three hold: it's **reversible** (a
checkpoint restores exactly what changed — a fix that runs a command has
nothing to store, so it's never Auto-fix), **recoverable in practice**
(nothing that can cut off your own access, like SSH auth or firewall policy,
even if the edit itself reverses cleanly), and **unambiguous** (exactly one
correct remediation). Failing that makes a finding Review when there are
alternatives to choose from, and Manual when there is only one thing to do
and no way to make it safe. The full procedure is on
[Fixing & rollback](https://hostveil.seolcu.com/docs/fixing).

Applying a fix always shows you the exact diff or command, backs the original
file up to a checkpoint, and only then applies it. `hostveil rollback` restores
that backup. All three interfaces run on one engine, so a fix applied in any of
them can be undone from any of them.

## How the score works

The score is one number between 0 and 100, built so it cannot flatter a host.
Each detection domain is an axis with a fixed share of the 100; a domain that
did not run is reported N/A and the remaining caps are renormalized over it,
so a host without Docker is not quietly handed free points. If nothing ran at
all, the score is N/A rather than 100.

Inside an axis, each finding erodes what is left instead of subtracting a
fixed number of points — the tenth finding still costs something, unlike a
model that sums penalties and clamps at zero, where two findings exhaust the
axis and everything after is free.

Severity answers how urgent a finding is, not how bad it could turn out to be:

| Level | What it means | Takes |
| --- | --- | --- |
| **High** | Reachable or usable right now, from off the host, by someone holding nothing. | Half of what the axis has left |
| **Medium** | A boundary that gives way to a foothold, a guessed credential, or a local account. | An eighth |
| **Low** | Defence in depth. No known path today. | A sixteenth |

Two adjustments sit on top: the same finding ID repeated on one axis is
damped harmonically, so four services missing the same setting count as one
mistake made four times rather than four mistakes; and a finding nothing can
fix yet (an unpatched CVE) counts a quarter, since charging it in full would
pin a well-maintained host's axis at 0. The overall score also gets a name in
every interface: 80 and above is *in good shape*, 50 to 79 *middling*, 25 to
49 *exposed*, below 25 *wide open*.

The full model, including why each axis cap is the size it is, is on the
[Scoring](https://hostveil.seolcu.com/docs/scoring) page.

## Interfaces

<p align="center">
  <img src="site/assets/tui.png" width="820"
       alt="Hostveil's terminal UI: the same score and per-domain meters over a keyboard-driven findings list">
</p>

- **TUI** — keyboard-driven, and what you get when you run `hostveil` on a
  terminal.
- **Web** — `hostveil serve`, a localhost-bound dashboard. It prints a URL
  carrying a one-off access token; open that exact URL. Loopback keeps the
  dashboard off the network but not away from other accounts on the same
  machine, and it runs as root. For remote access, forward the port over SSH.
- **CLI** — scriptable `scan` / `fix` / `rollback` with `--json` output.

All three are thin layers over one shared engine, so they behave identically.

The TUI and the dashboard share five color themes: `onedark` (the default),
`gruvbox`, `nord`, `catppuccin` and `tokyonight`, and six screen arrangements
(`console` is the default). Press `t` or `l` in the TUI to pick one and have
it remembered, use the pickers in the dashboard's status bar, or set
`--theme`/`--layout` or `HOSTVEIL_THEME`/`HOSTVEIL_LAYOUT` explicitly.

The TUI and `scan` can also draw their status markers from a patched
[Nerd Font](https://www.nerdfonts.com/) instead of plain Unicode: `--glyphs nerd`,
or `HOSTVEIL_GLYPHS=nerd`. This is opt-in rather than detected, since a
terminal cannot be asked what font it is using. See
[Interfaces](https://hostveil.seolcu.com/docs/interfaces) for theme
screenshots and Nerd Font details.

## AI (optional, advisory only)

`hostveil explain <id> --ai` adds a plain-language explanation from a local LLM
(Ollama by default), so nothing leaves your host. AI is strictly advisory and
never applies changes. Every explanation, score and fix works with no AI at
all.

**The one request Hostveil makes on its own** is a once-a-day check of the
GitHub releases page, to notice that a newer version exists. It sends nothing
about your host and the answer is cached; `HOSTVEIL_NO_UPDATE_CHECK=1` turns
it off. Nothing else in Hostveil contacts the network unless you ask it to —
`update`, and Trivy pulling vulnerability data during a CVE scan.

## Roadmap

A new detection domain is a bigger change than it looks — a new axis, funded
by taking weight from every existing one — so it ships as a named release, not
a line in a patch note: AI agent runtimes (3.1.0), kernel hardening (3.6.0),
the Docker daemon (3.8.0), service hardening (3.9.0). Next up, at the same low
cost as adding an entry to an existing registry: more self-hosted AI agent
runtimes, more reverse proxies, wider distro coverage for the measurement
harness. Under active exploration, not committed: Proxmox VE host hardening, a
scoped single-node k3s/k0s domain, and a fleet view across hosts reached over
SSH — with no new account, server or database, because that line is one this
project does not cross. And a short list of things ruled out on purpose, not
missing because nobody got to them: a plugin/rule system, AI that applies
fixes unattended, a hosted dashboard. The full list, and why, is on the
[Roadmap](https://hostveil.seolcu.com/docs/roadmap) page.

## Build from source

```bash
go build ./cmd/hostveil
go test ./...
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for full setup (per-platform
demo VM, repo layout, contributing checklist).

## License

[GPL-3.0](LICENSE)

> Team 내컴퓨터누가해킹했어 ([@gkdms04](https://github.com/gkdms04), [@seolcu](https://github.com/seolcu))
