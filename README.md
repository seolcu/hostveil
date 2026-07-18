# hostveil

> 2026-1 Ajou SoftCon 개발부문 최우수상 수상

**hostveil finds the security mistakes on your self-hosted Linux server, explains them in plain language, and fixes them safely.**
One binary, no config file, no cloud account.

[![CI](https://github.com/seolcu/hostveil/actions/workflows/ci.yml/badge.svg)](https://github.com/seolcu/hostveil/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/seolcu/hostveil)](https://goreportcard.com/report/github.com/seolcu/hostveil)
[![Release](https://img.shields.io/github/v/release/seolcu/hostveil)](https://github.com/seolcu/hostveil/releases/latest)
[![Go Version](https://img.shields.io/github/go-mod/go-version/seolcu/hostveil)](go.mod)
[![License: GPL-3.0](https://img.shields.io/github/license/seolcu/hostveil)](LICENSE)

[Website](https://hostveil.seolcu.com/) · [Latest release](https://github.com/seolcu/hostveil/releases/latest)

---

Self-hosting is booming, but most people running Jellyfin, Nextcloud, a
game server, or a local LLM are not security experts — and a single
misconfiguration can turn into a serious breach. hostveil is a **guided
hardening tool** for exactly those people. Point it at a Linux server: it
scans the highest-impact areas, merges everything into one 0–100 score,
explains each finding without jargon, and walks you through fixing it —
showing the exact change, backing up the original first, and letting you
undo any fix with one command.

## What it checks

| Domain | What it looks at | Needs |
| --- | --- | --- |
| **Docker / Compose** | Privileged mode, Docker socket mounts, exposed datastores and admin panels, host networking, unsafe bind mounts, missing no-new-privileges, hardcoded secrets, and more — a native audit of your Compose files | Docker |
| **SSH** | Root login, password authentication, empty passwords, weak brute-force limits, X11 forwarding — parsed natively from `sshd_config` | — |
| **Firewall** | Whether ufw, firewalld, or nftables is actually active | — |
| **Auto-updates** | Whether unattended-upgrades (apt) or dnf-automatic (dnf) is enabled | — |
| **Image CVEs** *(optional)* | Known vulnerabilities in the images your Compose services run | Trivy |

Missing Docker or Trivy? Those domains are skipped cleanly and the score is
renormalized so you are never handed a misleadingly perfect result.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
```

Trivy is optional — install it any time to enable image CVE scanning.

## Usage

```bash
hostveil                 # interactive TUI (default on a terminal)
hostveil scan            # print a scored report (add -v for details, --json for JSON)
hostveil fix <id>        # preview, then apply the fix for one finding
hostveil fix --all       # apply every safe (Auto) fix at once
hostveil rollback <id>   # undo a previously applied fix
hostveil history         # list applied fixes and their rollback IDs
hostveil explain <id>    # explain a finding (add --ai for a local-LLM second opinion)
hostveil serve           # web dashboard on 127.0.0.1:8787
```

Some checks (SSH, firewall) read root-owned files. Run with `sudo` for full
coverage; without it, those domains are skipped with a clear message.

## How fixing works

Every finding is classified so the tool never mutates blindly:

- **Auto** — one clearly-correct change. You still see it first.
- **Review** — several valid alternatives; you choose one.
- **Manual** — no safe automation; hostveil explains what to do instead.

Applying a fix always **shows the exact diff or command**, **backs up the
original file to a checkpoint**, then applies it. `hostveil rollback`
restores the backup — and because every UI (CLI, TUI, web) goes through the
same engine, a fix applied anywhere is reversible.

## Interfaces

- **TUI** — keyboard-driven, the default when you run `hostveil` on a terminal.
- **Web** — `hostveil serve`, a localhost-bound dashboard.
- **CLI** — scriptable `scan` / `fix` / `rollback` with `--json` output.

All three are thin layers over one shared engine, so they behave identically.

## AI (optional, advisory only)

`hostveil explain <id> --ai` adds a plain-language explanation from a local
LLM (Ollama by default), so nothing leaves your host. AI is strictly
advisory — it never applies changes — and every explanation, score, and fix
works with no AI at all.

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
