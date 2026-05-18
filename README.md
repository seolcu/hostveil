# hostveil

Linux self-hosting security dashboard. Scans Docker Compose stacks for common security misconfigurations.

## Quick Start

```sh
# Run a scan with an interactive TUI
hostveil

# Scan a specific compose file
hostveil --compose /path/to/docker-compose.yml

# JSON output
hostveil --compose ... --output json

# Start web UI
hostveil --compose ... --serve --port 8080
```

## Features

- **Compose Scanning** — Analyzes docker-compose.yml for 30+ security issues
- **Service-Aware Rules** — Service-specific checks for Vaultwarden, Jellyfin, Nextcloud, and 20+ other services
- **Host Auditing** — SSH, firewall, kernel, filesystem, and 6 other host check modules
- **External Adapters** — Trivy (vulnerabilities), Dockle (best practices), Lynis (host hardening), Gitleaks (secrets)
- **Fix Engine** — Preview and apply automatic fixes to your compose files
- **TUI** — Interactive terminal UI with filters, search, themes, and detail views
- **Web UI** — HTMX-powered web dashboard (`--serve`)
- **Export** — JSON, SARIF, Markdown, HTML

## Installation

```sh
curl -fsSL https://github.com/seolcu/hostveil/releases/latest/download/hostveil_linux_amd64 -o /usr/local/bin/hostveil
chmod +x /usr/local/bin/hostveil
```

## Build from Source

Requires Go 1.24+.

```sh
git clone https://github.com/seolcu/hostveil.git
cd hostveil
go build -o hostveil ./cmd/hostveil/
```

## License

GPL-3.0
