# scan

The single-tool dispatcher. The TUI, the Web UI, and the rescan
handler all call `RunSingleTool` rather than reaching into the
individual scanner packages.

## Files

- **`scan.go`**  `RunSingleTool(live, fixes, tool)`, the
  per-tool `ScanningMessage`, the `summarizeScanError` helper, and
  the `overrideCVEClassifications` post-processor that demotes CVE
  findings without a `FixedVersion` to `RemediationManual`.

## Tool names

The dispatcher knows about three tools:

| `tool` argument | Backing scanner | LookPath check? |
|-----------------|-----------------|-----------------|
| `"compose"` | `composeaudit.ScanAll` | No (runs in-process) |
| `"trivy"` | `trivy.ScanAll` | Yes |
| `"lynis"` | `lynis.Scan` | Yes |

For external tools, `RunSingleTool` calls `exec.LookPath(tool)` first
and sets the tool status to `ToolSkipped` with "Not found (run
'hostveil setup')" if the binary is missing.

## Result handling

Each scanner returns `([]domain.Finding, error)`. The dispatcher:

- If `error == nil`: classifies findings with the fix registry, runs
  the CVE override, and sets the tool status to `ToolDone`.
- If `error != nil` and `len(findings) > 0`: classifies and adds the
  partial findings, then sets the tool status to `ToolDegraded`
  with a one-line error summary.
- If `error != nil` and `len(findings) == 0`: sets the tool status
  to `ToolError`.

`finalizeIfDone` is called at the end of every dispatch. It checks
`live.AllToolsDone()` and, if so, calls `live.Finalize()` and saves
a scan record to history (best-effort).

## Public API

```go
// Run a single tool, classify the findings, and update the live
// snapshot. Idempotent if the tool is already done.
func RunSingleTool(live *domain.ScanProgress, fixes *fix.Registry, tool string)

// Human-readable "scanning X..." message used in the loading UI.
func ScanningMessage(tool string) string
```

## Tests

`scan_test.go` covers the dispatch logic and the degraded-status
path. Run with `go test ./internal/scan/...`.
