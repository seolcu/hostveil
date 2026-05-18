---
name: hostveil-browser-tui-qa
description: Use this skill when the user wants to visually QA hostveil's Bubbletea TUI through `--serve`, verify the ttyd browser terminal, drive the UI with keyboard input, capture multiple screenshots via agent-browser, and inspect the images for rendering issues. Trigger this for requests like "run hostveil --serve and take screenshots", "check the TUI in browser", "use agent-browser to test hostveil", "capture overview/findings/help/settings screens", or any browser-based visual review of hostveil's terminal UI.
---

# Hostveil Browser TUI QA

This skill verifies hostveil's web terminal mode end-to-end:

- Build `hostveil`.
- Run `./hostveil --serve` with a representative compose fixture.
- Connect through `agent-browser` to the ttyd page.
- Focus the terminal input and drive the Bubbletea TUI with keyboard events.
- Capture diverse screenshots.
- Open the screenshots and report concrete visual observations.

Use this skill for visual QA, regression checks, screenshot collection, or confirming that ttyd streams the actual TUI correctly in a browser.

## Dependencies

- `agent-browser` installed and usable from PATH.
- The `agent-browser` skill should be loaded before driving the browser.
- `ttyd` installed and usable from PATH.
- Go toolchain available for `go build`.
- Run from the hostveil repository root unless the user provides another path.

## Default Inputs

Use these defaults unless the user specifies otherwise:

- Binary: `./hostveil`
- Build command: `go build -o hostveil ./cmd/hostveil/`
- Serve command: `./hostveil --serve --port 8080 --compose tests/scenarios/vaultwarden-domain/docker-compose.yml`
- Screenshot directory: `hostveil-screenshots/`
- Desktop viewport: `1280x720`
- Narrow viewport: `720x720`

If `8080` is busy, hostveil should print a fallback URL. Parse the actual URL from the server log instead of assuming a port.

## Recommended Fast Path

Use the bundled script for the standard workflow:

```bash
.agents/skills/hostveil-browser-tui-qa/scripts/capture-hostveil-tui.sh
```

Optional flags:

```bash
.agents/skills/hostveil-browser-tui-qa/scripts/capture-hostveil-tui.sh \
  --compose tests/scenarios/vaultwarden-domain/docker-compose.yml \
  --out hostveil-screenshots \
  --port 8080
```

After it finishes, read the generated PNG files with the image-capable file reader and report findings.

## Manual Workflow

Follow this when the script fails or when the user asks for custom navigation.

1. Build hostveil:

```bash
go build -o hostveil ./cmd/hostveil/
```

2. Start `--serve` detached and capture logs:

```bash
rm -f /tmp/hostveil-serve.log
setsid -f ./hostveil --serve --port 8080 --compose tests/scenarios/vaultwarden-domain/docker-compose.yml > /tmp/hostveil-serve.log 2>&1
sleep 3
```

3. Parse the URL from `/tmp/hostveil-serve.log`. Prefer the line:

```text
Hostveil web interface running on http://127.0.0.1:PORT/
```

4. Open the URL and focus the terminal:

```bash
agent-browser open http://127.0.0.1:PORT/
agent-browser set viewport 1280 720
agent-browser wait 2500
agent-browser snapshot -i
agent-browser click @e1
```

The textbox ref is usually `@e1`, but refs are invalidated after navigation or viewport changes. Always run `agent-browser snapshot -i` before clicking a ref.

5. Capture these standard screens:

```bash
agent-browser screenshot hostveil-screenshots/01-overview.png
agent-browser press 2
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/02-findings-list.png
agent-browser press Enter
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/03-findings-detail.png
agent-browser press h
agent-browser wait 300
agent-browser press s
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/04-findings-severity-filter.png
agent-browser press 3
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/05-history.png
agent-browser press '?'
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/06-help.png
agent-browser press '?'
agent-browser wait 300
agent-browser press S
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/07-settings.png
agent-browser press right
agent-browser wait 500
agent-browser screenshot hostveil-screenshots/08-settings-theme-changed.png
agent-browser press S
agent-browser wait 500
agent-browser press 1
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/09-overview-theme-changed.png
agent-browser press h
agent-browser wait 700
agent-browser screenshot hostveil-screenshots/10-host-triage.png
agent-browser press 1
agent-browser wait 500
agent-browser set viewport 720 720
agent-browser wait 1000
agent-browser screenshot hostveil-screenshots/11-overview-narrow.png
```

6. Inspect every screenshot directly. Do not just report that files exist. Look for:

- Missing or clipped header/footer.
- Background color gaps, especially after ANSI reset codes.
- Broken borders or panel alignment.
- Text overflow in Findings detail.
- Modal centering and contrast in Help/Settings.
- Theme changes actually applying.
- Responsive behavior at narrow viewport.
- Browser/ttyd scrollbars that suggest terminal/container height mismatch.

7. Clean up:

```bash
agent-browser close >/dev/null 2>&1 || true
pkill -f "hostveil.*--serve" 2>/dev/null || true
pkill -f "ttyd.*hostveil" 2>/dev/null || true
```

If `pkill` times out or misses a process, inspect with `ps aux | rg 'hostveil|ttyd'` and kill only the test processes you started. Do not kill unrelated root-owned ttyd sessions or other user work.

## Report Format

Keep the final report concise and concrete:

```markdown
Captured N screenshots in `hostveil-screenshots/`.

Verified:
- --serve started on <url> with port fallback if any.
- agent-browser connected and keyboard input worked.
- Screens covered: overview, findings list/detail/filter, history, help, settings, theme change, host triage, narrow viewport.

Visual findings:
- <issue or "No obvious rendering breakage found.">

Notes:
- <e.g. ttyd page scrollbar observed, if applicable>
```

## Common Pitfalls

- `agent-browser` refs become stale after navigation, viewport changes, or DOM updates. Re-run `snapshot -i` before using `@eN`.
- Background server processes can be killed when the shell tool times out. Use `setsid -f` for the serve process.
- `8080` is often busy. Trust the logged URL, not the requested port.
- The ttyd page may show a browser scrollbar even when the TUI itself is fine. Report it separately from TUI rendering issues.
- Do not use vhs for this workflow; Chrome process management has been unreliable here.
