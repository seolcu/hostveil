# TUI Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document is the locked contract for the `hostveil tui`
subcommand (Spec FR-021..FR-023). It is enforced by
`tests/contract/tui_test.go` (which uses `teatest` to drive the
TUI model and snapshot the rendered output).

The TUI is build-tag-gated: when `hostveil` is built with the
`notui` tag, the `tui` subcommand is replaced by a stub that
prints a one-line "built without TUI" message and exits `0`.

---

## Invocation

```
hostveil tui [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--host-id` | UUID \| empty | most recent | Which host's findings to show. Defaults to the most recently scanned host. |
| `--category` | csv \| empty | all | Filter to one or more categories. |
| `--severity` | csv \| empty | all | Filter to one or more severities. |
| `--no-color` | bool | auto-detect | Disable ANSI styling. |
| `--ai` | bool | false | Enable the "AI explain" action. When the user invokes it, the AI layer is consulted (see `contracts/ai.md`). |

### Startup behavior

1. Verify that stdin and stdout are TTYs. If either is not a TTY,
   print `hostveil tui requires a TTY; run from an interactive
   terminal` to stderr and exit with code `0` (per FR-022).
2. Verify that `state.db` exists and has at least one `ScanRun`.
   If not, print a one-line message pointing at
   `hostveil scan` and exit with code `0`.
3. Open a `TUISession` row in the database (started_at = now,
   terminal dimensions captured).
4. Render the initial view.

---

## Layout (default first paint)

```
┌─ Hostveil v3.0.0 — homelab ─────────────────── 12 findings, 3 high ─┐
│                                                                      │
│  ▸ [high]  SSH: Root login is allowed over SSH                       │
│    [high]  Docker: Container runs as root                           │
│    [high]  Image CVE: nginx:1.25.3 has 4 known CVEs                 │
│    [med]   SSH: Password auth is enabled                            │
│    [med]   Firewall: UFW is inactive                                │
│    [med]   Sysctl: IP forwarding is enabled                         │
│    [low]   Updates: 7 pending security updates                       │
│    ... 5 more ...                                                   │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│ ↑/↓ navigate · enter expand · f fix · e explain · ai AI explain · q quit │
└──────────────────────────────────────────────────────────────────────┘
```

Rules:
- The header shows the hostname, total finding count, and high
  severity count.
- The list is grouped by category in a fixed order (SSH, Docker,
  image CVE, reverse proxy, SSL/TLS, hardening) and within each
  group is ordered by severity (critical → high → medium → low),
  then by `rule_id`.
- The footer is a one-line help bar with the available keys.
- The terminal width is auto-detected; the layout is
  column-aware and degrades gracefully on narrow terminals
  (≥ 60 columns: full layout; < 60 columns: list only, no
  per-finding location hint).

---

## Keyboard protocol (locked)

| Key (vim) | Key (arrow) | Action |
|---|---|---|
| `j` / `↓` | down | Move selection to the next finding in the list. |
| `k` / `↑` | up | Move selection to the previous finding. |
| `g` / `Home` | first | Move selection to the first finding. |
| `G` / `End` | last | Move selection to the last finding. |
| `Enter` / `l` / `→` | expand | Expand the selected finding to show its full plain-language explanation (the same content `hostveil explain` produces). |
| `Esc` / `h` / `←` | collapse | Collapse the expanded view back to the list. |
| `f` | fix | Open the "apply fix" flow for the selected finding (see below). |
| `e` | explain | Same as `Enter` (alias for muscle memory from `less`). |
| `a` | ai | When `--ai` is set: send the selected finding to the AI provider and show the response in a side-by-side panel. When `--ai` is not set: print a one-line hint that AI is disabled. |
| `/` | search | Open a fuzzy search prompt; the list filters as the user types. |
| `r` | refresh | Re-read the most recent `ScanRun` from the database. No-op when no new run exists. |
| `?` | help | Toggle the help bar. |
| `q` / `Ctrl+C` | quit | Close the TUI; close the `TUISession` row with `exit_reason=user-quit`. |

When the user is in the "apply fix" flow:

| Key | Action |
|---|---|
| `y` | Confirm and apply. |
| `n` / `Esc` | Cancel; return to the list. |
| `Tab` | Move focus to the "restart service?" prompt. |

---

## "Apply fix" flow inside the TUI

The TUI does NOT implement its own fix logic. It calls into the
same `internal/fix` package that the CLI uses, and shows the
result inline. The flow is:

1. The TUI renders the same preview that `hostveil fix` would
   show: file path, current line, proposed line.
2. The TUI prompts `Apply this fix? (y/n)`.
3. On `y`, the TUI calls the same internal function the CLI's
   `fix` subcommand calls. The user sees the result in a one-
   line confirmation at the bottom of the screen.
4. If the fix requires a service restart, the TUI prompts
   `Restart <service>? (y/n)`. On `n`, the fix is recorded with
   `restart_deferred=true`.
5. The TUI re-runs the affected category in-process (no new
   `ScanRun` is recorded; the existing row is updated to
   reflect the resolution).
6. The selection moves to the next finding in the list.

The TUI never asks for the sudo password itself; the program
either already has a cached elevated process (per FR-018's
batched-elevation model) or surfaces the elevation failure as
a one-line message and offers to "skip and continue".

---

## "AI explain" action

When the user presses `a` and `--ai` is set, the TUI:

1. Sends a redacted prompt (per `contracts/ai.md`) to the
   configured default provider (Ollama for v3.0.0).
2. Renders the response in a side-by-side panel (the static
   explanation on the left, the AI response on the right).
3. Persists an `AIRequest` row for audit.
4. On provider failure, shows the static explanation with a
   one-line `AI unavailable: <reason>; showing static explanation`
   hint.

The AI panel never becomes the *only* explanation; the static
one is always present alongside it.

---

## State persistence

- `TUISession` rows are written at start (with `terminal_cols`,
  `terminal_rows`, `color_enabled`) and updated at end (with
  `ended_at`, `exit_reason`, `findings_expanded`,
  `fix_actions_triggered`).
- The TUI does not write `Finding` rows; the CLI's `scan` is
  the only writer.
- The TUI's view of the data is a read-only projection of
  `state.db`; closing the TUI does not lose data.

---

## Error and edge-case behavior

| Situation | Behavior |
|---|---|
| Non-TTY (stdin or stdout) | One-line message, exit `0`. |
| `state.db` missing | One-line message pointing at `hostveil scan`, exit `0`. |
| `state.db` has no `ScanRun` | One-line message pointing at `hostveil scan`, exit `0`. |
| `state.db` is locked by another process | Retry up to 3 times with a 200 ms backoff; on final failure, one-line error and exit `2`. |
| Terminal resized | Layout reflows; the selection cursor is preserved by `rule_id`. |
| User kills the terminal (SIGTERM) | `TUISession` row is closed with `exit_reason=killed` via a signal handler. |
| Built with `notui` tag | Stub subcommand prints "built without TUI" and exits `0`. |
| AI provider failure | Side panel shows "AI unavailable"; static panel remains. |
| "Apply fix" needs elevation not yet granted | One-line message: "this fix needs elevation; run `hostveil scan` first to grant it". |
| Pressing `f` on a finding with no built-in fix | One-line message: "no built-in fix for this finding". |
