# hostveil

Linux self-hosting security scanner. Scans running Docker Compose projects
and the host system for security misconfigurations, and lets you inspect
the results and apply fixes from either a terminal UI or an embedded Web UI.

## What it does

hostveil runs three categories of checks and merges them into a single
score and finding list:

- **Docker Compose misconfigurations** — privileged mode, host network,
  sensitive mounts, added capabilities, missing `no-new-privileges`,
  missing healthchecks, no memory/CPU limits, secrets in compose files, etc.
  Audited natively by `hostveil` itself; no extra tool needed.
- **Container image CVEs** — vulnerabilities in the base images your
  compose services run. Scanned with [Trivy](https://github.com/aquasecurity/trivy).
- **Host hardening** — SSH config, firewall, kernel parameters, file
  permissions, audit/logging settings, etc. Scanned with [Lynis](https://github.com/CISOfy/lynis).

Every finding has a fix attached. Press `f` in the TUI or click the Fix
button in the Web UI to apply it. Some fixes apply automatically; others
offer a choice or require manual steps.

## Screenshots

<table>
  <tr>
    <td align="center"><b>TUI</b> (default <code>hostveil</code>)</td>
    <td align="center"><b>Web UI</b> (<code>hostveil serve</code>)</td>
  </tr>
  <tr>
    <td><img src="docs/images/tui.png" alt="TUI dashboard" width="100%"></td>
    <td><img src="docs/images/web.png" alt="Web UI dashboard" width="100%"></td>
  </tr>
</table>

> Screenshots are representative of recent versions. Some recent UI polish
> (Total card gradient, search input affordance, "Rescan" rename) may
> differ slightly in your build.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/seolcu/hostveil/main/scripts/install.sh | bash
hostveil
```

The installer prompts to install `trivy` and `lynis`, then drops the
`hostveil` binary into `/usr/bin`. `hostveil` re-execs via `sudo`
automatically because host-level scanning needs root.

Prefer a browser? Run `hostveil serve` and open <http://127.0.0.1:8787>.

If a tool is missing, the corresponding category is skipped gracefully
(no crash). Re-run the installer with `hostveil setup` to add it.

## Commands

| Command | Action |
|---------|--------|
| `hostveil` | Scan compose projects + host, open TUI |
| `hostveil serve` | Scan, serve Web UI on `127.0.0.1:8787` |
| `hostveil web` | Alias for `hostveil serve` |
| `hostveil serve --addr HOST:PORT` | Serve the Web UI on a custom address |
| `hostveil serve --fixture F` | Serve fixture data (E2E testing) |
| `hostveil setup` | Install/update dependencies (trivy, lynis) |
| `hostveil update` | Upgrade hostveil to the latest release |
| `hostveil --no-update` | Skip the automatic update check on startup |
| `hostveil --version` | Show installed version |

## How it works

```
docker compose ls
  → native compose audit (privileged, caps, mounts, env, secrets, ...)
  → Trivy: config + image scan
  → Lynis: host audit
       ↓
  merge findings + classify (auto / review / manual / unavailable)
       ↓
  axis-based score (0–100, four weighted axes)
       ↓
  TUI (default) or Web UI (`hostveil serve`)
```

## Understanding the score

The score is a weighted sum across four axes, each with its own penalty
cap so a single category can't dominate:

| Axis | Max penalty | What it covers |
|------|-------------|----------------|
| Vulnerabilities | 35 | Container image CVEs from Trivy |
| Container exposure | 30 | Compose misconfigurations (privileged, host network, mounts, etc.) |
| Host hardening | 25 | Lynis findings (SSH, firewall, kernel, file perms, ...) |
| Secrets | 10 | Hardcoded secrets detected in compose / `.env` files |

Color tier: green ≥ 85, lime ≥ 65, yellow ≥ 40, orange ≥ 20, red < 20.
Fixed findings stop counting toward the score. When the scan yields zero
findings the plate shows **Clean** instead of `100/100`, to avoid
implying a "perfect" scan.

## Remediation kinds

Every finding gets one of four kinds, attached by the fix registry
(`internal/fix/`). The four kinds are about **fixability**, not danger.

| Kind | When | Example |
|------|------|---------|
| **Auto** | One clear solution. The user still clicks Apply. | `chmod 640 /etc/shadow`, `sysctl -w net.ipv4.ip_forward=0` |
| **Review** | Multiple valid options, or the fix needs user input. | "Choose bridge or overlay network", "What UID should this container use?" |
| **Manual** | Cannot be automated — needs site-specific data or no upstream fix exists. | LDAP setup, a CVE with no `FixedVersion` available yet |
| **Unavailable** | Not yet implemented (the default before classification). | n/a — transient, never user-visible after a complete scan |

**Warning vs Review.** An Auto fix may still show a warning dialog if it
could break things (e.g. restarting a service). The warning is about
**side effects**, not about the choice. A Review fix means there are
genuinely multiple valid answers and the user must pick one.

For deeper design rationale — counter-examples, the multi-action
splitting rules, the action-success patterns — see
[`AGENTS.md`](AGENTS.md#remediationkind-classification-rules).

## TUI controls

| Key | Action |
|-----|--------|
| `j`/`↓`, `k`/`↑` | Navigate findings list |
| `Enter` | Open finding detail |
| `Esc` / `h` | Close detail view |
| `/` | Search findings |
| `f` | Apply fix (dry-run shown first) |
| `Space` | Select/deselect for batch fix |
| `Ctrl+A` | Select/deselect all visible |
| `0`–`4` | Filter by severity (0=all, 1=critical, …) |
| `s` | Cycle source filter (all → trivy → lynis → compose) |
| `r` | Cycle remediation filter |
| `o` | Cycle sort order |
| `O` | Toggle sort direction (asc/desc) |
| `v` | Cycle service filter |
| `R` (twice) | Clear all filters |
| `g` / `G` | Go to top / bottom |
| `Ctrl+R` | Recalculate score |
| `Ctrl+S` | Rescan all tools |
| `e` | Export report (JSON/CSV) |
| `?` | Toggle help |
| `q` | Quit |

## Web UI

```bash
hostveil serve
```

Default address: <http://127.0.0.1:8787>. The Web UI is served from the
same single binary — no Node.js, npm, or frontend build step.

Custom address:

```bash
hostveil serve --addr 127.0.0.1:9000
```

API endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Embedded Web UI (app.js, app.css) |
| `/api/health` | GET | Health check — returns `{"status":"ok"}` |
| `/api/result` | GET | Full scan result as JSON |
| `/api/fix` | POST | Apply or preview (`info_only`) a fix for a finding |
| `/api/fix/batch` | POST | Apply fixes for multiple findings |
| `/api/rescan` | POST | Trigger full rescan (trivy + lynis) |
| `/api/recalc` | POST | Recalculate score without rescanning |
| `/api/export?format=json\|csv` | GET | Export findings as JSON or CSV download |

## Requirements

- Linux (tested on Fedora, Ubuntu, Debian; macOS works for the binary
  but Docker-based checks assume Linux)
- Docker Engine 24+ (for compose project discovery)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Lynis](https://github.com/CISOfy/lynis)

Root access is required for host-level scanning. `hostveil` re-execs
via `sudo` automatically.

## Security considerations

- The process runs as **root** for the duration of the scan so that
  Lynis can read system files and fix actions can write them. The
  re-exec preserves the current environment.
- The Web UI binds to `127.0.0.1:8787` by default. Binding to
  `0.0.0.0` (`--addr 0.0.0.0:8787`) exposes host scan results to your
  network — use only in trusted environments.
- If the requested port is already in use, `hostveil` reclaims it by
  signalling the listener PID (SIGTERM, then SIGKILL) before binding.
  Be careful on shared hosts.
- Fixes are previewed as a dry-run before applying. No silent system
  modifications.

## Common questions

**How is this different from running `trivy` and `lynis` separately?**
hostveil unifies the output, runs the scans in parallel, scores
everything on a single 0–100 axis system, and — most importantly —
attaches a fix workflow to each finding. The native compose audit is
also hostveil's own; you don't get those rules from either upstream tool.

**Is the score deterministic across runs?**
Trivy results can shift slightly as its vulnerability database updates.
Lynis is deterministic for a given system state. The scoring formula
itself is deterministic given the same finding set.

**Can I add custom rules?**
Yes. Add a new `Fix` in `internal/fix/compose.go` (for compose rules)
or `internal/fix/system.go` (for host rules). The fix registry
classifies findings by ID, so any ID you register gets a remediation
kind set automatically. See
[`AGENTS.md`](AGENTS.md#remediationkind-classification-rules) for the
classification rules.

**Does hostveil modify my system without asking?**
No. Every fix is shown as a dry-run / preview first, with an explicit
Apply confirmation. The TUI shows a diff preview; the Web UI shows the
same plus the command that will run.

**Why a single binary with two UIs?**
Zero install footprint for the Web UI — no Node, no npm, no frontend
build chain. The TUI and Web UI render the same scan data via a single
in-memory snapshot. Updates to hostveil update both UIs at once.

**What if a tool is missing?**
hostveil skips the missing tool and shows it in the loading screen.
Run `hostveil setup` to install it. The remaining tools still scan;
the score simply reflects the categories that ran.

**Does hostveil persist scan history?**
No. Scans are in-memory only. Resets on restart. This is intentional —
hostveil is a "scan now and act" tool, not a continuous monitor.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layout, data flow,
  scoring model, concurrency boundaries.
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — local workflow, build
  commands, test layout, conventions.
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — how to file issues,
  submit a PR, add a new fix rule.
- [SECURITY.md](SECURITY.md) — threat model, what hostveil protects
  against, how to report a vulnerability.
- [CHANGELOG.md](CHANGELOG.md) — release notes and breaking changes.
- [AGENTS.md](AGENTS.md) — in-repo agent guide with the actual
  conventions the codebase uses (for AI agents and humans alike).

## License

GPL-3.0
