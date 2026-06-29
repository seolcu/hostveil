# history

Fix checkpoints and scan history, persisted to disk.

## Layout

The base directory is `/var/lib/hostveil`:

```
/var/lib/hostveil/
├── checkpoints/
│   └── 20260101-120000-abcd1234/
│       ├── meta.json           # Checkpoint metadata
│       └── files/
│           └── etc_ssh_sshd_config   # Backup of the file as it was
│                                    # before the fix was applied
└── scans/
    ├── 20260101-120000.json   # ScanRecord (Snapshot at scan time)
    └── 20260101-130000.json
```

`BaseDir`, `CheckpointDir`, `ScanDir`, `BackupSubdir`,
`MaxScans`, `MaxCheckpoints` are constants in `history.go`.

## Files

- **`history.go`** — `Checkpoint`, `Backup`, `Restart`, `ScanRecord`,
  plus the `Save*` / `List*` / `Get*` API. `cleanupOldScans` keeps
  `MaxScans` records on disk.
- **`rollback.go`** — `Rollback(checkpoint)` restores the backup
  files for a checkpoint. `RestartService(restart)` runs the
  service restart hint after a rollback.

## Public API

```go
// Create the directory structure on disk.
func EnsureDirs() error

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
func Rollback(cp Checkpoint) (RollbackResult, error)
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

## What's missing

- No tests. The package is exercised end-to-end by the Web UI
  and TUI tests via `hostveil serve` and `hostveil rollback`.
- No `Cleanup` API to apply `MaxScans` / `MaxCheckpoints` on
  disk. The caps are read-side only.
