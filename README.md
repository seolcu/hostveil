# hostveil

Linux self-hosting security scanner.

Scans your running Docker Compose projects and host system for security
misconfigurations, then helps you fix them.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
hostveil
```

The installer prompts to install `trivy` and `lynis` automatically,
then downloads the `hostveil` binary to `/usr/bin`.

If a tool is not installed, `hostveil` skips it and shows how to install:
`run 'hostveil setup'` to open the installer again.

## Commands

| Command | Action |
|---------|--------|
| `hostveil` | Scan compose projects + host, open TUI |
| `hostveil setup` | Install/update dependencies (trivy, lynis) |
| `hostveil update` | Upgrade hostveil to the latest release |
| `hostveil --no-update` | Skip the automatic update check on startup |
| `hostveil --version` | Show installed version |

## How it works

```
docker compose ls
  → Trivy: config + image scan
  → Lynis: host audit
  → merge + score
  → TUI
```

- **Trivy** scans every running compose project for IaC misconfigurations
  (privileged containers, host network mode, sensitive mounts, etc.)
  and CVE vulnerabilities in service images.
- **Lynis** audits the host system for hardening gaps (SSH config,
  firewall status, kernel parameters, file permissions, etc.).
- Results are combined into a single score (0–100) and displayed in a
  terminal UI. Findings list is navigable with arrow keys; press Enter
  to view details and fix instructions.
- On startup, `hostveil` checks GitHub for a newer release and notifies
  you. Use `--no-update` to disable.

## Features

- Single binary. Parallel scanning. Auto-detects running compose projects.
- Graceful skip: if trivy or lynis is missing, scans that tool is skipped
  with a clear message—no crashes.
- Fix engine (coming soon): apply fixes from the TUI with one key.

## Requirements

- Linux (tested on Fedora, Ubuntu, Debian)
- Docker Engine 24+ (for compose project discovery)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Lynis](https://github.com/CISOfy/lynis)

Root access is required for host-level scanning. `hostveil` re-execs
via `sudo` automatically.

## TUI controls

| Key | Action |
|-----|--------|
| `j`/`↓`, `k`/`↑` | Navigate findings list |
| `Enter` | Open finding detail |
| `Esc` | Close detail view |
| `s` | Open theme selector |
| `?` | Toggle help |
| `q` | Quit |

## Development

```bash
git clone https://github.com/seolcu/hostveil
cd hostveil
go build -o hostveil ./cmd/hostveil/
./hostveil
```

Tag a release:

```bash
git tag v2.0.1
git push origin v2.0.1
# GitHub Actions runs goreleaser automatically
```

Minimum Go version: 1.24.

## License

GPL-3.0
