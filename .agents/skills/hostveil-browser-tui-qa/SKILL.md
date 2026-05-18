---
name: hostveil-browser-tui-qa
description: Use this skill when the user wants to visually QA hostveil's Bubbletea TUI through `--serve`, verify the ttyd browser terminal, drive the UI with keyboard input, capture screenshots via agent-browser, and inspect the images for rendering issues. The agent runs an iterative Observe–Explore loop: each screenshot's visual analysis drives the next exploration decision, with a ≤20 screenshot budget. Trigger this for requests like "run hostveil --serve and take screenshots", "check the TUI in browser", "use agent-browser to test hostveil", "capture overview/findings/help/settings screens", or any browser-based visual review of hostveil's terminal UI.
---

# Hostveil Browser TUI QA

This skill enables an AI agent to autonomously perform visual QA on hostveil's Bubbletea TUI via `agent-browser` + ttyd.

**No fixed screenshot script exists.** The agent drives an iterative Observe–Explore loop: capture → inspect → decide → next capture. Each screenshot's visual analysis informs the next exploration step. Total screenshots **≤20** per run.

## Dependencies

- `agent-browser` installed and usable from PATH
- The `agent-browser` skill should be loaded before driving the browser
- `ttyd` installed and usable from PATH
- Go toolchain available for `go build`
- Run from the hostveil repository root unless the user provides another path

## Phase 1: Setup

### 1. Build

```bash
go build -o hostveil ./cmd/hostveil/
```

### 2. Start server (detached)

```bash
rm -f /tmp/hostveil-serve.log
setsid -f ./hostveil --serve --port 8080 --compose tests/scenarios/vaultwarden-domain/docker-compose.yml > /tmp/hostveil-serve.log 2>&1
sleep 3
```

If `8080` is busy, hostveil auto-increments. Parse the actual URL from the log:

```bash
URL=$(grep -Eo 'http://127\.0\.0\.1:[0-9]+/' /tmp/hostveil-serve.log | tail -n 1)
echo "$URL"
```

### 3. Connect agent-browser

```bash
agent-browser open "$URL"
agent-browser set viewport 1400 800
agent-browser wait 2500
```

The ttyd page has a terminal text input. Use `snapshot -i` to find its ref and click it:

```bash
agent-browser snapshot -i
agent-browser click @e1
```

The ref (`@e1`) is invalidated after navigation or viewport changes — re-run `snapshot -i` before clicking.

### 4. Keyboard input

Use `agent-browser press <key>` to send keystrokes. Bubbletea responds to single-character keys.

Wait **500–700 ms** between key presses and **800–1200 ms** after viewport changes (the terminal needs to reflow).

## Phase 2: Iterative Observe–Explore Loop

This is not a linear script. It is an **adaptive investigation**: you take a screenshot, inspect it, and let what you see guide the next move. Each cycle deepens coverage where it matters most.

### The Loop

```
1. Pick a state to explore (viewport + screen + action)
2. Navigate there with keyboard input
3. Capture screenshot          ───→  count: +1, total ≤ 20
4. Read and inspect the PNG    ───→  note findings, questions
5. Decide: what should I check next based on what I just saw?
   → something fishy? zoom in on that component
   → looks clean? move to next underexplored area
6. Go to step 1
```

The loop terminates when:
- All major screens (Overview, Findings, History) are covered at 3+ viewport breakpoints.
- All modals (Help, Settings) are visually verified.
- All Findings sub-states (list, detail, fix preview, search, filter, sort, host triage) are captured at least once.
- Any suspicious finding from an earlier screenshot has been followed up.

**Total screenshots must never exceed 20.** Budget them deliberately:
- ~6–8 for the first wide viewport (covers most states)
- ~3–4 per additional viewport (only layout-sensitive states)
- Reserve 1–2 shots for follow-up investigation of anything suspicious

### Budget Planning Heuristic

| Viewport       | Suggested shots | What to cover                                      |
|----------------|-----------------|----------------------------------------------------|
| Wide (1400×8)  | 7–8             | All 4 screens + all Findings sub-states + modals   |
| Medium (640×4) | 3–4             | Overview, Findings list, Findings detail, 1 modal  |
| Narrow (400×3) | 3–4             | Overview, Findings list, History                   |
| Minimal (280×2)| 1–2             | "Too narrow" message, single-column overflow       |
| Follow-up      | 1–2             | Anything suspicious from earlier screenshots       |

Adapt these numbers dynamically. If wide viewport reveals a bug, spend more shots following it up. If everything is clean, move on.

### Viewport Selection

The TUI has responsive breakpoints at character widths:

| Target layout  | Approx viewport px | What to expect                     |
|----------------|--------------------|------------------------------------|
| 3-column       | 1400×800           | Overview: 3 cards side-by-side     |
| 3-column tight | 900×600            | Overview: 3 cards, less margin     |
| 2-column       | 640×480            | Overview: 2 cards side-by-side     |
| 1-column       | 400×300            | Overview: cards stacked vertically |
| Too narrow     | 280×200            | "Terminal too narrow" message      |

Pick **3–4 sizes** that exercise different breakpoints.

### State Reference (What to Explore)

Use this table to decide **what state to navigate to next**. You don't need to capture all of them — let the loop guide you.

| Screen    | State               | Keyboard                          | What to verify                                          |
|-----------|---------------------|-----------------------------------|---------------------------------------------------------|
| Overview  | Default             | `1`                               | Score, grade, severity bars, axis cards, host info      |
| Overview  | Theme changed       | `S` → `right` → `S` → `1`        | Theme applies immediately, no background gaps           |
| Findings  | List                | `2`                               | Index numbers (` 1.`, ` 2.`), service column, filter bar |
| Findings  | Detail panel        | `Enter` on first finding          | Metadata 2-col, `───` separator, description/risk/fix   |
| Findings  | Fix preview         | `f` on a fixable finding          | YAML snippet with 3-line context, `- old` / `+ new`     |
| Findings  | Search mode         | `/` then type keyword, then Enter | Search bar renders, matches highlighted, results filter  |
| Findings  | Severity filter     | `s` to cycle                      | Filter chip shown, list narrows, index updates           |
| Findings  | Multi-filter        | `s` + `x` + `v` combos           | Multiple chips, filter bar overflow handling             |
| Findings  | Sort mode           | `o` to cycle                      | Sort indicator changes (source/title)                    |
| Findings  | Host triage         | `h` on Overview screen            | Empty state/scope-filtered, `No host-level findings`     |
| Findings  | Reset filters       | `R`                               | Returns to full unfiltered list                          |
| History   | Default             | `3`                               | Axis bars, severity summary, grouped info messages       |
| Help      | Modal overlay       | `?`                               | Centered, background dimmed, no black bars               |
| Settings  | Modal               | `S`                               | Theme selector, border, centered                         |
| Settings  | Theme cycled        | `right` → `right`                 | Selected theme changes, accent colors update             |

### Adaptive Branching Examples

When inspecting a screenshot, let your observations drive the next move:

| If you see...                                | Then next capture...                             |
|----------------------------------------------|--------------------------------------------------|
| Background gap after an ANSI reset           | Another viewport, same screen → is it consistent?|
| Text clipped in detail panel                 | Findings detail at wider/narrower viewport       |
| Modal off-center or has black bars           | Same modal at different viewport sizes           |
| Theme change looks incomplete                | Every screen after same theme change             |
| Filter bar text overflows awkwardly          | Same filter state at different widths            |
| History info messages not grouped properly   | Vaultwarden + another compose scenario           |
| Empty state missing icon or bad alignment    | All empty states (host triage, no filters, etc.) |
| Everything looks perfect at wide             | Narrow it down fast — that's where bugs hide     |

### When to Stop

Stop exploring when the marginal value of another screenshot is low:
- You've seen each screen at 3+ viewport resolutions.
- You've exercised every Findings sub-state at least once.
- No suspicious rendering pattern remains un-investigated.
- Your screenshot budget (20) is almost exhausted — reserve the last 1–2 for follow-ups.

## Phase 3: Visual Inspection Checklist

After capturing each screenshot, read the PNG file with the image-capable file reader and inspect for:

### General

- [ ] Header bar present, shows hostveil + score + finding count
- [ ] Footer bar present, shows navigation hints
- [ ] No black bars or terminal-default-background gaps between styled regions
- [ ] Full-width background color coverage (especially after ANSI reset codes)
- [ ] No browser scrollbar due to terminal/container height mismatch
- [ ] Borders intact, rounded properly, no broken corners
- [ ] Text not clipped or overflowing its container

### Overview

- [ ] Score card: grade color matches score (green ≥80, yellow ≥50, red <50)
- [ ] Severity card: counts match actual findings, icons present
- [ ] Axis bars: label + bar + score aligned
- [ ] Host card: hostname, docker version, load avg truncated to 1/5/15m
- [ ] Meta card: services count, findings count
- [ ] Responsive layout: 3/2/1 columns at expected viewports
- [ ] "Terminal too narrow" message at very small viewport

### Findings List

- [ ] Index numbers (` 1.`, ` 2.`) right-aligned
- [ ] Cursor `>` on selected item
- [ ] Severity labels with icons and colors
- [ ] Title truncated with `…` when too long
- [ ] Service column aligned

### Findings Detail

- [ ] Header with finding title, colored by severity
- [ ] Metadata in 2-column layout (ID, Severity, Axis, Scope | Source, Service, Fix)
- [ ] `───` separator line between metadata and content
- [ ] Description, Why it's risky, How to fix, Evidence sections
- [ ] "Fix: Auto (press f)" hint for fixable findings

### Fix Preview

- [ ] "Fix Preview: <title>" header
- [ ] YAML service block extracted with 3-line context
- [ ] Change summary clear

### Filters

- [ ] Filter bar shows natural language (e.g. "Severity: Critical", not "sev:critical")
- [ ] Format: `N/M  Severity: Critical | Source: Host`
- [ ] Overflow: when too long, wraps to new line
- [ ] No filter: shows `no filters`
- [ ] Sort indicator when changed

### Search

- [ ] `search:` prompt appears
- [ ] Matching text highlighted (inverse or underline)
- [ ] Non-matching items filtered out
- [ ] Esc cancels and restores original list

### History

- [ ] Axis score bars with labels
- [ ] Severity summary inline (colored)
- [ ] Info messages grouped ("Discovered N project(s): ...")
- [ ] Warnings shown with ⚠ icon

### Help Modal

- [ ] Centered on screen
- [ ] Background dimmed (overlay)
- [ ] Keyboard shortcuts grouped into Navigation/Filters/Actions sections
- [ ] No black bars around modal (background sequences applied correctly)

### Settings Modal

- [ ] Centered on screen
- [ ] Theme selector with `●` on selected, `○` on others
- [ ] Theme change via `right`/`left` keys applies immediately
- [ ] ─── separator, close hint at bottom

### Theme Changes

- [ ] All theme colors apply: Background, Surface, Border, Accent, severity colors
- [ ] No regressions in text readability
- [ ] Background stays solid after theme switch

## Phase 4: Cleanup

Always clean up background processes at the end:

```bash
agent-browser close >/dev/null 2>&1 || true
pkill -f "hostveil.*--serve" 2>/dev/null || true
pkill -f "ttyd.*hostveil" 2>/dev/null || true
```

If `pkill` fails or misses a process, use:

```bash
ps aux | rg 'hostveil|ttyd'
kill <PID>    # kill only test processes, not root-owned ttyd sessions
```

## Report Format

Present a concise, concrete report. Include the **iterative decisions** made during QA — show why each screenshot was taken and what the inspection revealed.

```markdown
Captured N screenshots in `hostveil-screenshots/`.

Setup:
- Built at <commit>
- Started on <URL> (port fallback if any)
- agent-browser connected and keyboard input confirmed

Viewport coverage: 1400×800, 640×480, 400×300, ...

Screens covered: overview, findings list/detail/fix-preview/search/filtered/sorted,
history, help, settings, theme change, host triage, narrow viewport, too-narrow.

Iterative investigation log:
- Shot #1 (1400×800, Overview): default state → clean, no issues
- Shot #2 (1400×800, Findings detail): [inspection notes → triggered shot #3]
- Shot #3 (1400×800, Fix preview): followed up on detail panel observation → ...
...

Visual findings:
- <finding 1: description, which screenshot, severity>
- <finding 2: ...>
- (or "No obvious rendering breakage found.")

Regressions:
- <any new issues not seen in prior QA>
