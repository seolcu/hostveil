# Architecture

hostveil is a single Go binary that runs three scanner backends in
parallel, merges their findings into a scored snapshot, and renders
that snapshot in either a terminal UI (Bubble Tea v2) or an
embedded Web UI (no frontend build chain). This document describes
the package layout, the data flow, the scoring model, and the key
concurrency boundaries.

## Package layout

```
cmd/hostveil/         main package, subcommands, signal handling
internal/
  domain/             shared types, scoring, scan progress
  scan/               single-tool dispatcher
  trivy/              Trivy adapter (config and image scan)
  lynis/              Lynis adapter (host hardening)
  composeaudit/       native Docker Compose audit
  compose/            YAML AST editing primitives
  fix/                fix registry: compose, system, image fixes
  history/            fix checkpoints and scan history on disk
  tui/                Bubble Tea v2 UI
  web/                embedded HTTP server and static Web UI
```

The `domain` package has no outbound dependencies on other internal
packages. It is the shared vocabulary. Every other internal
package imports it.

## Data flow

```
                ┌────────────┐
                │  main.go   │
                └─────┬──────┘
                      │ ensureSudo (re-exec via sudo)
                      │
                      ├─ goroutine ──→ scan.RunSingleTool("trivy")
                      ├─ goroutine ──→ scan.RunSingleTool("lynis")
                      └─ goroutine ──→ scan.RunSingleTool("compose")
                                            │
                                            ▼
                                 composeaudit / lynis / trivy
                                            │
                                            ▼
                                findings []domain.Finding
                                            │
                            ┌───────────────┴───────────────┐
                            ▼                               ▼
                  fix.Registry.Classify                AddFindings
                            │                               │
                            ▼                               ▼
                  remediation / how_to_fix         domain.ScanProgress
                                                            │
                                                            ▼
                                              domain.ScoreFindings
                                              (4-axis scoring)
                                                            │
                                                            ▼
                                                       Snapshot
                                                  ┌─────────┴─────────┐
                                                  ▼                   ▼
                                          tea.NewProgram       web.Serve
                                            (TUI)              (HTTP API)
```

Three scanners run concurrently. Each writes its own findings to
the shared `domain.ScanProgress`, which holds a `sync.RWMutex`
protecting the findings slice, the per-tool status map, and the
score. The score is recomputed under the write lock on every
state change.

When the last tool reports done, `ScanProgress.Finalize` is
called. It sets `Phase = "complete"` and computes the final
score. The same finalize hook saves a scan snapshot to history
on disk (best effort, never blocking the UI).

## Scoring model

Score is a weighted sum across four axes, each with its own
penalty cap.

| Axis | Max penalty | What it covers |
|------|-------------|----------------|
| Vulnerabilities | 35 | Trivy CVE findings |
| Container exposure | 30 | Compose misconfigurations (privileged, host network, mounts, ...) |
| Host hardening | 25 | Lynis findings (SSH, firewall, kernel, file perms, ...) |
| Secrets | 10 | Hardcoded secrets detected in compose / `.env` files |

Per-finding penalties are severity-based:

| Severity | Penalty |
|----------|---------|
| Critical | 8 |
| High | 5 |
| Medium | 2 |
| Low | 1 |

Penalty is summed per axis, capped at the axis's `MaxPenalty`,
then the axis score is `100 - penalty * 100 / maxPenalty`. Overall
score is `100 - sum(axis penalties)`, clamped to `[0, 100]`.

Findings marked `Fixed = true` are skipped during scoring.
Duplicate findings (same `Source`, `ID`, and `Service`) are
deduped. Trivy can report the same CVE for multiple services on
the same image, and Lynis can report the same test ID multiple
times for different configs.

The "Clean" indicator appears on the UI when the scan yields
zero findings, to avoid implying a "perfect" 100/100 result.

## Concurrency

The `domain.ScanProgress` struct is the single source of truth
for in-flight state. All reads and writes go through it.

- `AddFindings`, `SetToolStatus`, `SetUpdateAvailable`,
  `MarkFixed`, `MarkRelatedFixed`, `Finalize`, `Recalculate`,
  `ResetForRescan` all take the write lock.
- `Snapshot`, `AllToolsDone`, `ToolState` take the read lock.
- `Snapshot` returns a deep copy, so the Web UI can poll
  `/api/result` without synchronizing with the scanner
  goroutines.

Scanner goroutines are short-lived: each `scan.RunSingleTool`
call runs the scanner, writes its findings, sets the tool
status, and returns. There is no long-lived goroutine holding
the lock.

The Bubble Tea `Update` method takes the model by value
(Bubble Tea v2 pattern), so the TUI's model is immutable across
Updates. The model holds a `*domain.ScanProgress` pointer.
Updates from background goroutines (e.g. the fix batch progress)
call `m.send` to push a message into the program's queue, which
then triggers a normal Update.

## Fix flow

Each `fix.Fix` has a `FindingID`, a `Label`, and a list of
`Action`s. A fix is registered once at startup in
`fix.RegisterAll`. Findings are classified by the registry at
scan time. `Classify` writes the remediation kind and
`how_to_fix` text onto each finding.

At apply time, the user picks an action index. Both the Web UI
handler and the TUI's fix dispatch call the same
`history.ApplyWithCheckpoint(fix, finding, actionIdx)`, which:

1. Rejects invalid action indexes with a clear error.
2. For `ActionEdit` actions with a resolvable file path, creates a
   checkpoint (backs up the file before the action runs).
3. Runs the action. For `ActionEdit` this is a real mutation.
   For `ActionExec` it is a shell command.
4. On success with a backup, saves the checkpoint with the
   resulting diff and a `Restart` hint, so `hostveil rollback`
   can re-apply the backup and prompt to restart the affected
   service.

The caller (Web UI handler or TUI) then, on success, marks the
finding as `Fixed`. If the fix was registered for an exact ID (not
a wildcard pattern), the caller also marks any related findings on
the same service as fixed, so the user does not have to fix the
same problem multiple times. Because both UIs go through
`ApplyWithCheckpoint`, a fix applied from the TUI is just as
rollback-able as one applied from the Web UI.

## Remediation kinds

Every finding has a `Remediation` field that the user sees in
the UI as a colored chip.

| Kind | When | Example |
|------|------|---------|
| `Auto` | One clear solution. The user still clicks Apply. | `chmod 640 /etc/shadow` |
| `Review` | Multiple valid options, or the fix needs user input. | "Choose bridge or overlay network" |
| `Manual` | Cannot be automated. | CVE with no `FixedVersion` available yet |
| `Unavailable` | Not yet implemented. Never user-visible after a complete scan. | n/a |

The distinction between `Auto` and `Review` is the source of
the most subtle bugs in this codebase. The design rules are in
`AGENTS.md`. In particular, a single-action fix must be
`Auto` even if its `Warning` field is non-empty. A `Review`
fix must offer independent alternatives. Bundling N settings
into one action forces the user to accept all or none.

## Web UI

The Web UI is a single static page
(`internal/web/assets/index.html`, `app.css`, `app.js`) served by
`internal/web/server.go`. The frontend is plain ES2020+ with no
build step. `app.js` is served as-is, and all rendering is done
by hand-rolled template strings.

State management is a single global `state` object plus a
`setInterval` poll on `/api/result` while the scan is loading.
The poll is paused on `visibilitychange` to avoid hammering the
server while the tab is hidden.

The dashboard renders both the overall score and the four-axis
`ScoreBreakdown` from `/api/result`, so users can see which capped
category — vulnerabilities, container exposure, host hardening, or
secrets — is driving the score.

Modal overlays (fix confirmation, action selection, batch
progress, export, help) are rendered as `position: fixed`
divs appended to `document.body`. They are styled with the
same theme tokens as the main UI.

## Persistence

- **In-memory snapshot**: the only authoritative state for the
  current scan. Lost on restart.
- **Scan history**: `internal/history` writes a JSON record per
  scan to `/var/lib/hostveil/scans/` (capped at 30 records).
  Used by `hostveil history --scans` to show what changed
  between runs.
- **Fix checkpoints**: `internal/history` writes a checkpoint
  directory per fix application to
  `/var/lib/hostveil/checkpoints/` (capped at 100 records).
  Used by `hostveil rollback <id>` to restore the pre-fix
  state of any edited file.

There is no database. The in-memory snapshot is intentionally
transient. hostveil is a "scan now and act" tool, not a
continuous monitor.
