# hostveil

**English** · [한국어](README.ko.md)

> 2026-1 Ajou SoftCon 개발부문 최우수상 수상

**hostveil finds the security mistakes on your self-hosted Linux server, explains them in plain language, and fixes them safely.**
One binary, no config file, no cloud account.

[![CI](https://github.com/seolcu/hostveil/actions/workflows/ci.yml/badge.svg)](https://github.com/seolcu/hostveil/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/seolcu/hostveil)](https://github.com/seolcu/hostveil/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/seolcu/hostveil)](go.mod)
[![License: GPL-3.0](https://img.shields.io/github/license/seolcu/hostveil)](LICENSE)

[Website](https://hostveil.seolcu.com/) · [Docs](https://hostveil.seolcu.com/docs/) · [Latest release](https://github.com/seolcu/hostveil/releases/latest)

<p align="center">
  <img src="site/assets/web.png" width="900"
       alt="hostveil's web dashboard: a 0–100 security score, per-domain meters, and findings grouped by severity with one-click safe fixes">
</p>

---

Most people running Jellyfin, Nextcloud, a game server or a local LLM at home
are not security experts, and one bad default is enough to lose the box.
hostveil is a hardening tool for those servers. Run it and it checks the places
that matter most, gives you a single 0–100 score, describes each problem
without jargon, and offers to fix it. It shows you the change before making it,
backs up the file first, and lets you undo any fix with one command.

## What it checks

Findings are named after the domain that found them. The prefix in the second
column is what you pass to `hostveil fix` and `hostveil explain`.

| Domain | Findings | What it looks at | Needs |
| --- | --- | --- | --- |
| **Docker / Compose** | `compose.*` | Privileged mode, Docker socket mounts, exposed datastores and admin panels, host networking, unsafe bind mounts, shared PID and IPC namespaces, writable root filesystems, missing no-new-privileges, hardcoded secrets, and more. Your Compose files are audited natively, and so are containers started with a plain `docker run` | Docker |
| **SSH** | `ssh.*` | Root login, password authentication, empty passwords, weak brute-force limits, login grace time, gateway ports, host-based and keyboard-interactive auth, X11 forwarding. Parsed from `sshd_config` directly, following `Include` into `sshd_config.d/` | — |
| **Firewall** | `firewall.*` | Whether ufw, firewalld, nftables or iptables is actually active, and whether published container ports are quietly bypassing it | — |
| **Auto-updates** | `updates.*` | Whether unattended-upgrades (apt) or dnf-automatic (dnf) is enabled | — |
| **Exposed services** | `ports.*` | Host processes listening on a non-loopback address, read from `ss`. This is the natively installed database, admin panel or app that a Compose audit cannot see | `ss` |
| **Accounts** | `accounts.*` | Non-root accounts with root's UID (0), and login accounts with an empty password, parsed from `/etc/passwd` and `/etc/shadow` | root (for `/etc/shadow`) |
| **File permissions** | `fileperms.*` | Over-permissive modes on `/etc/shadow`, `/etc/passwd`, `/etc/group`, `sshd_config`, and SSH host private keys | — |
| **AI agent runtimes** | `agent.*` | Self-hosted agent runtimes, OpenClaw and Hermes Agent: a gateway reachable off-host, authentication turned off on one that is, unrestricted shell and elevated tools, a disabled sandbox, and loose permissions on the config and the API keys beside it | — |
| **Kernel hardening** | `sysctl.*` | Eight kernel parameters read straight from `/proc/sys`: the quiet knobs that stop a local foothold from becoming root and a spoofed packet from becoming a route. No `sysctl` binary needed | — |
| **Docker daemon** | `dockerd.*` | The daemon underneath your containers. An API served over TCP without TLS client verification is unauthenticated root for anyone who can reach the port; hostveil also checks for a world-writable socket, who holds the socket's group, and the defaults for no-new-privileges, userns-remap and live-restore | Docker |
| **Service hardening** | `systemd.*` | The units you installed yourself, read as systemd's own *effective* configuration: whether a service can gain privileges through setuid, write to `/usr` and `/etc`, read every user's home directory, or share `/tmp` with the rest of the host. Distribution units are left to the distribution | systemd |
| **Image CVEs** *(optional)* | `cve.*` | Known vulnerabilities in the images your Compose services run | Trivy |

If Docker or Trivy is missing, those domains are skipped and the score is
renormalized over the ones that ran, so a partial scan never comes back as a
misleadingly perfect result.

## Install

```bash
curl -fsSL https://hostveil.seolcu.com/install.sh | bash
```

If you would rather not pipe a script into a shell, which is a reasonable
position for a security tool, install a native package from the
[latest release](https://github.com/seolcu/hostveil/releases/latest):

```bash
sudo apt install ./hostveil_<version>_linux_amd64.deb   # or dnf install ./hostveil-<version>.x86_64.rpm
```

The package puts the same binary in the same place (`/usr/bin/hostveil`), so
either route works. Docker and `iproute2` are recommended but not required.
Without them, those domains report N/A instead of failing the scan.

To build it yourself you need Go 1.26 or later:

```bash
go install github.com/seolcu/hostveil/cmd/hostveil@latest
```

Trivy is optional. Install it whenever you want image CVE scanning.

To **upgrade**, run the same command again. It replaces the binary and leaves
your saved scans and rollback checkpoints alone. To **uninstall**:

```bash
curl -fsSL https://hostveil.seolcu.com/install.sh | bash -s -- --uninstall
```

That removes the binary and prints where the state directory is without
deleting it. Those checkpoints are the backups of every file hostveil has
edited on the host, and you may well still want to undo one after uninstalling.

Release archives are built by GitHub Actions and carry a signed build
provenance attestation, so you can confirm a download really came from this
repo's release workflow before you run it:

```bash
gh attestation verify hostveil-linux-amd64.tar.gz --repo seolcu/hostveil
```

Each archive also ships an SBOM (`.sbom.json`) listing what went into the
binary.

## Usage

```bash
hostveil                 # interactive TUI (default on a terminal)
hostveil scan            # print a scored report (add -v for details, --json for JSON)
hostveil fix <id>        # preview, then apply the fix for one finding
hostveil fix --all       # apply every safe (Auto) fix at once
hostveil fix --all --review  # and the Review ones too, after reading what they are
hostveil rollback <id>   # undo a previously applied fix
hostveil history         # list applied fixes and their rollback IDs
hostveil explain <id>    # explain a finding (add --ai for a local-LLM second opinion)
hostveil serve           # web dashboard on 127.0.0.1:8787 (open the printed URL)
```

Some checks read root-owned files, and applying a fix needs root, so hostveil
re-runs itself under `sudo` when it has to. You get the same password prompt as
`sudo hostveil` and it carries on in the same terminal afterwards. `version`
and `help` never prompt.

For scripts and CI, set `HOSTVEIL_NO_SUDO=1`. The root-only domains are then
skipped with a message saying so.

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

`--sarif` writes SARIF 2.1.0 instead, the format GitHub code scanning and most
CI systems ingest. There is one rule per finding ID and a stable fingerprint
per finding, so a consumer can follow a single finding across scans. The score
and the per-domain coverage travel in the run's properties, because a SARIF
file with no results reads as a clean host and a scan that could not look
produces exactly that. `--output FILE` writes whichever format you picked. The
exit status never varies by format or destination; the exit code is the
contract.

`--only` and `--skip` narrow a run to some domains (`--only ssh,firewall`). The
domains that did not run report N/A rather than 100, and a partial scan is
deliberately not saved as the baseline for the next delta.

Exit code **3** is worth wiring up. A failed domain contributes no findings, so
without it an unreachable Docker socket silences the two heaviest axes and the
pipeline sees a clean run. To a consumer that never reads the output, a blind
scan and a healthy host look identical. A domain skipped for a missing
dependency, or one that managed only partial coverage, does not change the exit
status; both are reported in the output instead.

Other commands exit 0 on success, 1 on failure and 2 on a usage error.

### When something looks wrong

`HOSTVEIL_DEBUG=1` traces every command hostveil runs against the host to
stderr: what ran, how long it took, and whether it failed.

```bash
HOSTVEIL_DEBUG=1 hostveil scan
```

Attach that to a bug report about a domain being skipped or a check reporting
the wrong thing. Command *output* is never logged, deliberately: `docker
inspect` prints the resolved environment of every container, so a trace that
included it would leak credentials as a matter of routine.

See [Troubleshooting](https://hostveil.seolcu.com/docs/troubleshooting) for what
Degraded, a declined rollback, an empty history and exit code 3 mean.

## How fixing works

Every finding is classified, so the tool never changes anything blindly:

- **Auto** — one clearly correct change. You still see it first.
- **Review** — several valid alternatives; you pick one.
- **Manual** — nothing safe to automate, so hostveil explains what to do
  instead.

Applying a fix always shows you the exact diff or command, backs the original
file up to a checkpoint, and only then applies it. `hostveil rollback` restores
that backup. All three interfaces run on one engine, so a fix applied in any of
them can be undone from any of them.

## How the score works

The score is one number between 0 and 100, and it is built so that it cannot
flatter a host.

Each domain is an axis with a fixed share of the 100: container exposure 14,
SSH 14, CVEs 10, firewall 9, exposed services 8, AI agent runtimes 8, updates
7, accounts 7, the Docker daemon 7, service hardening 6, kernel hardening 5,
file permissions 5. Only the domains that actually ran are counted. A skipped
one is reported N/A and the remaining caps are renormalized over it, so a host
without Docker is not quietly handed 14 free points. If nothing ran at all, the
score is N/A rather than 100.

Inside an axis, each finding erodes what is left instead of subtracting a fixed
number of points:

```
remaining  = remaining × (1 − weight)      for each finding
axis score = cap × remaining
```

One High finding takes half the axis, a Medium an eighth, a Low a sixteenth.
Because every finding takes a share of the remainder, the axis approaches zero
without reaching it, and the tenth finding still costs something. The model
this replaced summed penalties and clamped at zero, so two findings exhausted
most axes and everything after them was free: a host with 27 container findings
scored the same as one with 3.

Two adjustments sit on top of that.

- **The same finding ID repeated on one axis is damped.** Four services all
  missing `no-new-privileges` is one mistake made four times, not four separate
  mistakes, so the second instance costs half its weight and the third a third.
  It never reaches zero: at ten the mistake is systematic, which is worse than
  one and not ten times worse.
- **A finding nothing can fix yet counts a quarter.** Every image ships CVEs
  with no upstream patch. Charging those in full pins the axis at 0 for a
  perfectly maintained host, and charging nothing would pretend the risk isn't
  there.

The full model, including why each cap is the size it is, is on the
[Scoring](https://hostveil.seolcu.com/docs/scoring) page.

### Does it actually work?

hostveil's own score going up after hostveil's own fixes proves nothing. The
same code decides what counts as a finding and what the number should be
afterwards. So the repository carries a harness that measures a seeded host
with tools that have never heard of hostveil: Lynis, Docker's CIS benchmark, a
TCP scan from off the host, and the kernel's own list of listening sockets.

The host is a real ARM64 server seeded like an ordinary self-hosted box.
Nextcloud with PostgreSQL, Jellyfin with Redis, Portainer with Watchtower,
every port on `0.0.0.0`, root SSH login allowed, no firewall, no automatic
updates.

| Measured by | Before | After `fix --all --review` |
| --- | --- | --- |
| **Ports answering from off the host** | 7 | **1** |
| CIS Docker Benchmark (pass / warn) | 16 / 16 | **20 / 12** |
| Lynis hardening index | 57 | **61** |
| hostveil's SSH domain | 18/100 | **100/100** |
| hostveil score | 40 | **59** |

The host that produces those numbers is `scripts/measure/seed.sh`, in this
repository, so the run above is one you can reproduce rather than one you have
to take on trust.

Five of those ports went quiet when the services restarted into their new
Compose files: PostgreSQL, Redis, Nextcloud, Jellyfin and Portainer. The sixth
is the interesting one. It is a natively installed Redis that hostveil reports
and then declines to fix, because the config file differs per datastore and the
finding does not carry its path — and it stopped answering anyway, because
hostveil turned the firewall on. Only SSH still answers.

The kernel and the scanner disagree at that point, and both are right: two
sockets are still bound to a routable address, and one of them is reachable
from off the host. A bind address and a packet filter are different claims
about a port, so the page reports both.

Rollback restored every file the fixes changed, byte for byte: 5 of 5, across
33 checkpoints. Eight of the seventeen reviewed fixes leave nothing to roll
back at all — six image updates, enabling the firewall, and switching on
unattended-upgrades — and hostveil marks each of those `[not reversible]` in
its own history rather than implying the undo is total.

What did *not* move is published too. The container domain goes 0 → 2 out of
100, because what remains there is Manual by design: a Docker socket mounted
into Portainer, host networking, secrets in the environment. Two of Lynis's
three warnings are a second UID 0 account that hostveil finds and refuses to
delete, since `userdel` cannot be undone from a checkpoint. The AI-agent
domain barely moves either, 0 → 1: the file-mode findings are fixed and the
config ones are not, because OpenClaw's config is JSON5 that users comment
heavily and hostveil has no round-tripper for it. And the CVE domain went
*down*, 44 → 16: updating six images pulled six current tags, each with its
own published vulnerabilities. A newer image is not a patched one.

The numbers, the method, the instruments that did not move and the one that
cleared for the wrong reason are on the
[Measured results](https://hostveil.seolcu.com/docs/measurements) page. Run it
yourself with `scripts/measure/run.sh -c`, on a container or a throwaway VM
rather than your own machine.

## Interfaces

<p align="center">
  <img src="site/assets/tui.png" width="820"
       alt="hostveil's terminal UI: the same score and per-domain meters over a keyboard-driven findings list">
</p>

- **TUI** — keyboard-driven, and what you get when you run `hostveil` on a
  terminal.
- **Web** — `hostveil serve`, a localhost-bound dashboard. It prints a URL
  carrying a one-off access token; open that exact URL. Loopback keeps the
  dashboard off the network but not away from other accounts on the same
  machine, and it runs as root. For remote access, forward the port over SSH.
  Changing `--addr` will not expose it.
- **CLI** — scriptable `scan` / `fix` / `rollback` with `--json` output.

All three are thin layers over one shared engine, so they behave identically.

The TUI and the dashboard share five color themes: `onedark` (the default),
`gruvbox`, `nord`, `catppuccin` and `tokyonight`. Press `t` in the TUI to pick
one and have it remembered, use the picker in the dashboard's status bar, or
set it explicitly with `--theme nord` or `HOSTVEIL_THEME=nord`.

They share six screen arrangements as well. `console`, the default, puts a
domain rail down the left carrying every score and every coverage gap;
`split`, `triage`, `railverdict`, `lanes` and `inline` are the rest. Press `l`
in the TUI or use the dashboard's status-bar picker, and the choice is
remembered. `--layout console` and `HOSTVEIL_LAYOUT=console` set it too, on
both `hostveil` and `hostveil serve`. No single arrangement suits both a wide
window and an 80-column terminal, so the default answers the common case and
the picker answers the rest.

The TUI and `scan` can draw their status markers from a patched
[Nerd Font](https://www.nerdfonts.com/) instead: `--glyphs nerd`, or
`HOSTVEIL_GLYPHS=nerd` once. This is opt-in rather than detected, because a
terminal cannot be asked what font it is using and a missing glyph occupies the
same single cell a present one would. The default set is plain Unicode and
renders everywhere.

Any Nerd Font build works, Mono or not. The symbols come from the Font Awesome
block, which is present in every patched font and one cell wide in all of them.
The glyphs that go double-width in a non-Mono build are the Powerline and icon
ranges, which hostveil does not use.

## AI (optional, advisory only)

`hostveil explain <id> --ai` adds a plain-language explanation from a local LLM
(Ollama by default), so nothing leaves your host. AI is strictly advisory and
never applies changes. Every explanation, score and fix works with no AI at
all.

## How it compares

Most server-hardening tools are auditors: they hand you a report and leave the
fixing to you. hostveil is built to close that loop for people who aren't
security experts.

- **[Lynis](https://github.com/CISOfy/lynis)** is a thorough, expert-oriented
  host auditor. It prints a long list of suggestions but doesn't apply them,
  and reading the output assumes you already know which ones matter.
- **[docker-bench-security](https://github.com/docker/docker-bench-security)**
  checks a Docker host against the CIS benchmark. It's container-only, and it
  reports rather than fixes.
- **[Trivy](https://github.com/aquasecurity/trivy)** scans images and
  filesystems for known CVEs and misconfigurations. It's excellent at that one
  job, and hostveil actually *runs* Trivy for its CVE domain, but it doesn't
  look at your SSH config, firewall or accounts.

hostveil's angle is to merge the host, your containers and image CVEs into a
single 0–100 score, explain each finding in plain language, and then apply the
fix, with a preview, a backup and one-command rollback. One binary, and no
report to interpret.

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
