# hostveil

Linux self-hosting security scanner with an auto-fix engine.

Scans your running Docker Compose projects and host system for security
misconfigurations, then helps you fix them — automatically.

## Quick start

```bash
# Requirements
sudo apt install docker.io trivy lynis
sudo systemctl enable --now docker

# Run
hostveil
```

`hostveil` auto-detects running Docker Compose projects, scans each one
with Trivy (CVE + IaC misconfiguration), audits the host with Lynis,
and opens a terminal UI showing all findings.

Press `Enter` on a finding to see details and fix instructions.

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
- Results are combined into a single score (0–100) and displayed in
  a curses-style terminal UI.

## Features

- Single binary, no runtime dependencies beyond `trivy` and `lynis`.
- Parallel scanning — compose and host checks run at the same time.
- Auto-detects running projects via `docker compose ls` — no config.
- Fix engine (coming soon): apply fixes from the TUI with one key.

## Requirements

- Linux (tested on Fedora, Ubuntu, Debian)
- Docker Engine 24+ (for compose project discovery)
- [Trivy](https://github.com/aquasecurity/trivy) (`apt install trivy`)
- [Lynis](https://github.com/CISOfy/lynis) (`apt install lynis`)

Root access is required for host-level scanning. `hostveil` prompts
for sudo automatically if not run as root.

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

```
git clone https://github.com/seolcu/hostveil
cd hostveil
go build -o hostveil ./cmd/hostveil/
./hostveil
```

Minimum Go version: 1.24.

## License

GPL-3.0
