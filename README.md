# hostveil

**English** · [한국어](README.ko.md)

**hostveil finds the security mistakes on your self-hosted Linux server, explains them in plain language, and fixes them safely.**
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
       alt="hostveil's web dashboard: a 0–100 security score, per-domain meters, and findings grouped by severity with one-click safe fixes">
</p>

---

Most people running Jellyfin, Nextcloud, a game server or a local LLM at home
are not security experts, and one bad default is enough to lose the box.
hostveil is a hardening tool for those servers. Run it and it checks the places
that matter most, gives you a single 0–100 score, describes each problem
without jargon, and offers to fix it. It shows you the change before making it,
backs up the file first, and lets you undo any fix with one command.

## Does it actually work?

hostveil's own score going up after hostveil's own fixes proves nothing. The
same code decides what counts as a finding and what the number should be
afterwards. So the repository carries a harness that measures a seeded host
with tools that have never heard of hostveil: Lynis, Docker's CIS benchmark, a
TCP scan from off the host, and the kernel's own list of listening sockets.

The host is a real server seeded like an ordinary self-hosted box.
Nextcloud with PostgreSQL, Jellyfin with Redis, Portainer with Watchtower,
every port on `0.0.0.0`, root SSH login allowed, no firewall, no automatic
updates.

| Measured by | Before | After `fix --all --review` |
| --- | --- | --- |
| **Ports answering from off the host** | 7 | **1** |
| CIS Docker Benchmark (pass / warn) | 17 / 15 | **20 / 12** |
| Lynis hardening index | 57 | **60** |
| hostveil's SSH domain | 18/100 | **100/100** |
| hostveil score | 29 | **51** |

The host that produces those numbers is `scripts/measure/seed.sh`, in this
repository, so the run above is one you can reproduce rather than one you have
to take on trust.

Four of those ports went quiet when the services restarted into their new
Compose files: PostgreSQL, a Redis published on 6380, Portainer and Jellyfin.
Two more went at the reviewed stage, and they are the interesting ones. One is
the Docker daemon's own API on 2375 — unauthenticated root for anyone who can
reach it. The other is a natively installed Redis that hostveil reports and
then declines to fix, because the config file differs per datastore and the
finding does not carry its path. Neither was edited shut: hostveil turned the
firewall on. Only SSH still answers.

The kernel and the scanner disagree at that point, and both are right: three
sockets are still bound to a routable address, and one of them is reachable
from off the host. A bind address and a packet filter are different claims
about a port, so the page reports both.

Rollback restored every file the fixes changed, byte for byte: 8 of 8, across
48 checkpoints. Another 7 of the 18 reviewed fixes leave nothing to roll back
at all — the ones that are not file edits — and hostveil marks each of those
`[not reversible]` in its own history rather than implying the undo is total.

What did *not* move is published too. The container domain goes 0 → 2 out of
100, because what remains there is Manual by design: a Docker socket mounted
into Portainer, host networking, secrets in the environment. Account hygiene
does not move at all, 25 → 25, and Lynis agrees from the outside.
Two of Lynis's 4 warnings are the same accounts hostveil reports and refuses
to touch, since `userdel` cannot be undone from a checkpoint. The AI-agent
domain moves a
little, 0 → 5: the file-mode findings are fixed and the config ones are not,
because OpenClaw's config is JSON5 that users comment heavily and hostveil will
not re-encode it. The CVE domain is flat at 16, and the Docker daemon at 10.

Lynis is the sharpest instrument here for a reason that cuts against us: its
index moved 57 → 60 while **not one** of its 37 suggestions or 4 warnings
cleared. The index scores tests it does not print, so three points moved with
nothing in the printed list to show for it. A harness that reported only the
index would have looked better and said less.

The numbers, the method, the instruments that did not move and the one that
cleared for the wrong reason are on the
[Measured results](https://hostveil.seolcu.com/docs/measurements) page. Run it
yourself with `scripts/measure/run.sh -c`, on a container or a throwaway VM
rather than your own machine.

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
| **Docker daemon** | `dockerd.*` | The daemon underneath your containers. An API served over TCP without TLS client verification is unauthenticated root for anyone who can reach the port; hostveil also checks for a world-writable socket, who holds the socket's group, and the defaults for no-new-privileges, userns-remap and live-restore | Docker |
| **Service hardening** | `systemd.*` | The units you installed yourself, read as systemd's own *effective* configuration: whether a service can gain privileges through setuid, write to `/usr` and `/etc`, read every user's home directory, or share `/tmp` with the rest of the host. Distribution units are left to the distribution | systemd |
| **Reverse proxy** | `proxy.*` | The thing on 443 that everything else is behind. nginx read from `/etc/nginx`, following `include` into `conf.d` and `sites-enabled`, for deprecated TLS versions and directory listing; Traefik read from your Compose files, for the dashboard served in insecure mode — an unauthenticated page listing every backend address behind the proxy, and the setting nearly every Traefik tutorial tells you to add | — |
| **Image CVEs** *(optional)* | `cve.*` | Known vulnerabilities in the images your Compose services run | Trivy |

If Docker or Trivy is missing, those domains are skipped and the score is
renormalized over the ones that ran, so a partial scan never comes back as a
misleadingly perfect result.

hostveil can report **78 findings** across those domains, and **38 of them
carry a fix** — 25 hostveil will apply unattended, 13 only after you have read
the diff. The rest are Manual on purpose, and each one is named in the register
in [`internal/fix/register.go`](internal/fix/register.go) with the reason
hostveil will not touch it: deleting an account cannot be undone from a
checkpoint, removing a Docker socket mount breaks the tool that needs it, and
so on. Manual by decision, never Manual because nobody looked — a test fails
the build on the difference.

## How it's tested

hostveil runs as root and edits configuration files on servers people depend
on. That is a lot to ask, so this is what stands behind it.

- **There is more test code in this repository than product code.** Not a ratio
  anyone targets — it is what auditing an operating system honestly costs. A
  test enforces the inequality rather than a number that would be stale by the
  afternoon.
- **[`internal/docs/`](internal/docs) exists to fail the build when a published
  page drifts from the code.** Every domain table, every finding ID in a
  screenshot, every figure on the measured-results page, and the counts in the
  paragraph above are checked against what the program actually does. A stale
  number here is a failing build rather than something a reader has to catch.
- **5 fuzz targets run nightly**, five minutes each, over the YAML and JSON5
  editors that rewrite your config files and the parsers that feed them.
- **Every pull request drives the real binary end to end** — scan, fix,
  history, rollback, rescan — inside a seeded Debian container. It is the only
  place the apply and rollback machinery meets a real filesystem.
- **Every release target is cross-compiled on every pull request**, so a break
  appears while it is still a pull request rather than during a release.
- **[`demo/`](demo/README.md) is a Vagrant VM** seeded to be vulnerable, so you
  can watch a hardening tool edit a server before you let it near one of yours.

None of that answers whether the fixes change anything real. That is what the
harness in [`scripts/measure/`](scripts/measure) is for, and it is the section
above.

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

To **upgrade** or **uninstall**, hostveil does it itself:

```bash
hostveil update      # --check to ask without changing anything
hostveil uninstall
```

`update` works out how this binary was installed — the install script, a
`.deb`, an `.rpm`, or `go install` — and updates it the same way, so nothing
ends up disagreeing about what is on the host. Re-running the install script
over a packaged install would leave dpkg or rpm describing a file it no longer
owns. The download is checked against the release's checksums and, where the
GitHub CLI is present, against the signed build provenance.

Uninstalling removes the binary and prints where the state directory is without
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
hostveil history --scans # the score of every saved scan, oldest first
hostveil explain <id>    # explain a finding (add --ai for a local-LLM second opinion)
hostveil serve           # web dashboard on 127.0.0.1:8787 (open the printed URL)
hostveil update          # update this binary the way it was installed
hostveil uninstall       # remove it, keeping your checkpoints
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

| Kind | Meaning | hostveil can apply it |
| --- | --- | --- |
| **Auto-fix** | One clearly correct change. You still see it first. | Yes |
| **Review** | Two or more independent alternatives; you pick one. | Yes |
| **Manual** | Nothing safe to automate, so hostveil explains what to do instead. | No |
| **Unavailable** | A real problem with no fix in existence yet, such as a CVE with no published patch. | No |

`fix --all` applies only the Auto-fix ones. `fix --all --review` applies the
Review ones too, each through its first alternative — the command is where you
say you have read what they are.

**Applying a fix is not always a change the host has seen, and the score knows
the difference.** A Compose file is read when the container is recreated, a
systemd drop-in when the unit is reloaded, a sysctl drop-in at the next boot.
Until then the file is correct and nothing an attacker can see has changed, so
the finding stays charged and its row is marked `PEND`. `fix --all` says how
many are waiting and each fix names the command that puts it in force. A score
that moved on a host nothing had changed about would be measuring hostveil's
activity rather than your server.

A finding is Auto-fix only when applying it unattended is defensible without
you having looked at it, which takes all three of:

1. **Reversible.** The action leaves a checkpoint that restores exactly what it
   changed. A fix that runs a command has nothing to store, so it is never
   Auto-fix.
2. **Recoverable in practice.** If the change is wrong you must still be able
   to reach the machine to undo it. Anything that can cut off your own access,
   such as SSH authentication or firewall policy, fails this even when the
   edit itself reverses cleanly.
3. **Unambiguous.** Exactly one correct remediation, and applying it cannot
   break a legitimate configuration.

Failing one of the three makes a finding Review when there are two or more
alternatives to choose between, and Manual when there is only one thing to do
and no way to make it safe. The full procedure, including how a check and the
fix registry settle a disagreement, is on
[Fixing & rollback](https://hostveil.seolcu.com/docs/fixing).

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

Severity answers how urgent a finding is, not how bad it could turn out to be.
A scanner reading configuration cannot know what a compromise would cost you.
What it can see is how much stands between an attacker and the problem right
now, and that is what the three levels measure.

| Level | What it means | Takes |
| --- | --- | --- |
| **High** | Reachable or usable right now, from off the host, by someone holding nothing. Nothing has to be broken first. | Half of what the axis has left |
| **Medium** | A boundary that gives way to a foothold, a guessed credential, or a local account. | An eighth |
| **Low** | Defence in depth. No known path today; it narrows what a future compromise reaches. | A sixteenth |

Those three definitions are the whole taxonomy. The names only carry the order.
The High row is the anchor and the other two are defined against it, which is
why the gap between High and Medium is fourfold rather than one step.

Because every finding takes a share of the remainder, the axis approaches zero
without reaching it, and the tenth finding still costs something. The model
this replaced summed penalties and clamped at zero, so two findings exhausted
most axes and everything after them was free: a host with 27 container findings
scored the same as one with 3.

The overall score is also given a name in every interface: 80 and above is
*in good shape*, 50 to 79 *middling*, 25 to 49 *exposed*, below 25 *wide open*.

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

**The one request hostveil makes on its own** is a once-a-day check of the
GitHub releases page, from `scan`, `tui` and `serve`, to notice that a newer
version exists. It sends nothing about your host and the answer is cached.
`HOSTVEIL_NO_UPDATE_CHECK=1` turns it off; nothing else in hostveil contacts
the network unless you ask it to — `update`, and Trivy pulling vulnerability
data during a CVE scan.

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
