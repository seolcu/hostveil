# tui

The Bubble Tea v2 terminal UI. Renders the same `domain.Snapshot`
that the Web UI does.

## Files

- **`app.go`**  the Bubble Tea `tea.Model` and its `Init`, `Update`,
  and `View` methods. State, key handling, and message dispatch.
- **`keys.go`**  `updateMain` and `updateModal` key dispatch tables.
- **`filter.go`**  finding filters and sort logic.
- **`fix.go`**  fix dispatch (single + batch), fix dry-run, export.
- **`layout.go`**  fixed-width row and panel layout primitives.
- **`screen.go`**  `renderMain`, `renderLoading`, `renderDetail`,
  and the modal overlay renderer.
- **`theme.go`**  the single color theme.

## Architecture

Bubble Tea v2 uses a value-receiver `Update` method: the model is
copied on every Update, and the previous model is dropped. Anything
that needs to mutate state from a background goroutine (e.g. the
fix batch progress) goes through `m.send(msg)`, which pushes the
message into the program's message queue and triggers a normal
Update.

The model holds a `*domain.ScanProgress` pointer for the live
state. The TUI's `tickCmd` polls the snapshot every 100 ms while
the scan is loading, and at the same interval after loading to
auto-clear toasts.

## Key modes

- **Loading**  scan in progress. The user can press `q` to quit.
- **Main**  findings table + detail panel. Most keys live here.
- **Detail**  full-screen detail view. `j`/`k` scroll, `g`/`G` go
  to top/bottom, `Esc`/`h` returns to the main view.

Modal overlays (help, filter, dry-run, fix confirm, fix result, fix
progress, export) take precedence over main and detail.

## Style

- Lip Gloss v2 `NewLayer` / `NewCompositor` for modal overlays.
  Do not reintroduce manual ANSI string overlay slicing.
- TUI row rendering should keep fixed-width row invariants; avoid
  slicing styled strings.

## Tests

`internal/tui/app_test.go`, `screen_test.go` cover the rendering
and key dispatch logic. Run with `go test ./internal/tui/...`.
