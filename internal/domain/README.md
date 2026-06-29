# domain

The shared vocabulary every other internal package uses. No outbound
dependencies on other `internal/*` packages.

## Files

- **`types.go`** — `Finding`, `Severity`, `Source`, `RemediationKind`,
  and the `Finding.IsFixable` / `RemediationKind.IsFixable` helpers.
  The `Finding` struct is the central data model.
- **`scoring.go`** — the 4-axis scoring engine (`ScoreFindings`,
  `CalculateScore`, `ScoreBreakdown`, `ScoreAxis`).
- **`live.go`** — `ScanProgress`, the thread-safe in-memory state
  holder. The Web UI and TUI both read from this.
- **`defaults.go`** — timeouts and HTTP client config. Single source
  of truth for `domain.HTTPClientTimeout`, `domain.LynisAuditTimeout`,
  etc.
- **`exec.go`** — `CommandRunner` interface (for testability) and the
  `DefaultRunner` implementation.

## Concurrency

`ScanProgress` is the only type in the codebase with internal
synchronization. Every method that mutates state takes the write
lock; every read method takes the read lock. `Snapshot` returns a deep
copy so the Web UI can poll without coordinating with the scanner
goroutines.

## Public API

```go
// New starts a fresh scan progress holder.
func NewScanProgress(noUpdateCheck bool) *ScanProgress

// Add a batch of findings (under the write lock).
func (sp *ScanProgress) AddFindings(findings []Finding)

// Mark all findings matching this ID+service as Fixed.
func (sp *ScanProgress) MarkFixed(id string, service string) int

// Mark related findings (e.g. other CVEs in the same image) as Fixed.
func (sp *ScanProgress) MarkRelatedFixed(excludeID, service string, matchFn func(id string) bool) []string

// Finalize: switch phase to "complete" and recompute the score.
func (sp *ScanProgress) Finalize()

// Recalculate the score without changing findings.
func (sp *ScanProgress) Recalculate()

// Reset for a rescan: clear findings, reset tool statuses, keep the
// "update" tool state.
func (sp *ScanProgress) ResetForRescan()

// Take a thread-safe deep copy of the current state.
func (sp *ScanProgress) Snapshot() Snapshot

// Score a finding list. 0–100 overall plus per-axis breakdown.
func ScoreFindings(findings []Finding) ScoreBreakdown
```

## Tests

`internal/domain/live_test.go`, `scoring_test.go`, `types_test.go`
cover the public API. Run with `go test ./internal/domain/...`.
