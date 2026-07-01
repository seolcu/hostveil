# history

Fix checkpoints and scan history, persisted to disk.

## Layout

The base directory is `/var/lib/hostveil`:

```
/var/lib/hostveil/               (0700 — owner-only)
├── checkpoints/                 (0700)
│   └── 20260101-120000-abcd1234/    (0700)
│       ├── meta.json                # Checkpoint metadata (0600)
│       └── files/                   (0700)
│           └── etc_ssh_sshd_config  # Backup of the file as it was
│                                    # before the fix was applied
└── scans/                       (0700)
    ├── 20260101-120000.json     # ScanRecord (Snapshot at scan time) (0600)
    └── 20260101-130000.json
```

Every directory and file here is owner-only. hostveil always runs
as root, so in practice this means only root can read scan
snapshots or checkpoint diffs — see `SECURITY.md` at the repo root
for why (checkpoint diffs and scan snapshots can carry secrets).

`BaseDir`, `CheckpointDir`, and `ScanDir` are `var`, not `const`,
specifically so tests in this package can redirect them at a
`t.TempDir()` (see `withTempHistoryDirs` in `apply_test.go`).
Production code must never reassign them. `BackupSubdir`,
`MaxScans`, `MaxCheckpoints` are `const`.

## Files

- **`history.go`** — `Checkpoint`, `Backup`, `Restart`, `ScanRecord`,
  plus the `Save*` / `List*` / `Get*` API. `cleanupOldScans` keeps
  `MaxScans` records on disk.
- **`apply.go`** — `ApplyWithCheckpoint`, the single code path both
  the Web UI and the TUI use to run a fix action: backs up the
  target file (if any), runs the action, and saves a checkpoint on
  success. This is what makes `hostveil rollback` work regardless
  of which UI applied the fix.
- **`rollback.go`** — `Rollback(checkpoint)` restores the backup
  files for a checkpoint. `RestartService(restart)` runs the
  service restart hint after a rollback.

## Public API

```go
// Create the directory structure on disk, owner-only (0700).
// Also chmods directories that already exist, so upgrading from a
// hostveil version that created them with looser permissions
// self-heals on the next call.
func EnsureDirs() error

// Run a fix action, wrapping it in a checkpoint. The single entry
// point the Web UI and the TUI both use.
func ApplyWithCheckpoint(f *fix.Fix, finding *domain.Finding, actionIdx int) fix.FixResult

// Save a checkpoint (metadata + per-file backups already on disk).
func SaveCheckpoint(cp Checkpoint) error

// Take a backup of a file. Returns a Backup record to be added to
// the Checkpoint.
func BackupFile(checkpointDir, originalPath string) (*Backup, error)

// List checkpoints, newest first, capped at MaxCheckpoints.
func ListCheckpoints() ([]Checkpoint, error)

// Fetch a single checkpoint by ID.
func GetCheckpoint(id string) (*Checkpoint, error)

// Persist a scan snapshot (best-effort; called from a goroutine).
func SaveScan(snap domain.Snapshot) error

// List scan records, newest first, capped at MaxScans.
func ListScans() ([]ScanRecord, error)

// Roll back a checkpoint's edits.
func Rollback(cp Checkpoint) (*RollbackResult, error)
```

## Limits

- **`MaxScans = 30`** — only the 30 most recent scans are kept.
- **`MaxCheckpoints = 100`** — only the 100 most recent checkpoints
  are kept.

Both caps are enforced on `List*` reads, not on writes. The caps
are deliberately high to avoid surprising the user with silent
deletions of their fix history.

## Concurrency

`EnsureDirs` is safe to call from multiple goroutines — the
underlying `os.MkdirAll` is idempotent. `SaveCheckpoint` and
`SaveScan` are not safe to call concurrently for the same
checkpoint / scan ID, but the package only generates IDs with
`time.Now()` so collisions are not a concern in practice.

## Tests

`apply_test.go` covers `ApplyWithCheckpoint`: a successful
`ActionEdit` produces a restorable checkpoint (asserted via a full
apply → `ListCheckpoints` → `Rollback` round trip), an `ActionExec`
produces no checkpoint (nothing to back up), a failed `Apply` saves
no checkpoint, and an out-of-range action index is rejected.
`history_test.go` covers the `0700`/`0600` permission hardening,
including self-healing a directory that already exists with looser
permissions from an older hostveil version.

All tests use `withTempHistoryDirs(t)` to redirect
`BaseDir`/`CheckpointDir`/`ScanDir` at a `t.TempDir()` — never run
against the real `/var/lib/hostveil`.

## What's missing

- No `Cleanup` API to apply `MaxScans` / `MaxCheckpoints` on
  disk. The caps are read-side only.
