// Package history provides scan history and fix checkpoint management.
package history

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
)

// BaseDir, CheckpointDir, and ScanDir are vars (not const) so tests in
// this package can point them at a t.TempDir() instead of writing to the
// real /var/lib/hostveil. Production code must never reassign them.
var (
	BaseDir       = "/var/lib/hostveil"
	CheckpointDir = BaseDir + "/checkpoints"
	ScanDir       = BaseDir + "/scans"
)

const (
	BackupSubdir   = "files"
	MaxScans       = 30
	MaxCheckpoints = 100
)

// Checkpoint represents a restore point created before a fix is applied.
type Checkpoint struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	FindingID string    `json:"finding_id"`
	Service   string    `json:"service"`
	Action    string    `json:"action"`
	ActionIdx int       `json:"action_idx"`
	Diff      string    `json:"diff"`
	Backups   []Backup  `json:"backups"`
	Restart   *Restart  `json:"restart,omitempty"`
}

// Backup records a file that was backed up before modification.
type Backup struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	Mode         uint32 `json:"mode"`
}

// Restart records a service that may need restarting after rollback.
// Command is a list of arguments passed directly to exec.Command — no
// shell interpretation. The first element is the program; the rest are
// its arguments.
type Restart struct {
	ServiceName string   `json:"service_name"`
	Command     []string `json:"command"`
	Description string   `json:"description"`
}

// ScanRecord stores a scan snapshot for history comparison.
type ScanRecord struct {
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Snapshot  domain.Snapshot `json:"snapshot"`
}

// CheckpointID generates a short ID from timestamp and finding ID.
func CheckpointID(findingID string) string {
	now := time.Now()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", findingID, now.Format(time.RFC3339Nano), now.UnixNano())))
	return fmt.Sprintf("%s-%s", now.Format("20060102-150405"), hex8(hash[:]))
}

func hex8(b []byte) string {
	return fmt.Sprintf("%x", b[:4])
}

// EnsureDirs creates the base directory structure. Every directory is
// owner-only (0700): hostveil always runs as root, and checkpoints/scans
// can contain the contents of files a finding flagged as sensitive (e.g.
// an .env referenced by compose.dr004, or a diff whose context lines
// happen to include a secret next to an unrelated change). A world-
// readable directory here would let any local user read that content
// regardless of the backed-up file's own permissions.
//
// os.MkdirAll does not change the mode of a directory that already
// exists, so an explicit os.Chmod is needed to tighten permissions left
// behind by a hostveil version older than this check.
func EnsureDirs() error {
	for _, dir := range []string{BaseDir, CheckpointDir, ScanDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
	}
	return nil
}

// SaveCheckpoint persists a checkpoint to disk.
func SaveCheckpoint(cp Checkpoint) error {
	if err := EnsureDirs(); err != nil {
		return err
	}
	dir := filepath.Join(CheckpointDir, cp.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, BackupSubdir), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	// meta.json embeds cp.Diff, a unified diff of the edited file. That diff
	// can contain secrets that were sitting near an unrelated change (e.g.
	// a compose file's hardcoded password a few lines from a fixed
	// "privileged: true"), so this must never be world-readable.
	return os.WriteFile(filepath.Join(dir, "meta.json"), data, 0600)
}

// BackupFile copies a file to the checkpoint's backup directory.
// Returns a Backup record.
func BackupFile(checkpointDir, originalPath string) (*Backup, error) {
	info, err := os.Stat(originalPath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", originalPath, err)
	}
	data, err := os.ReadFile(originalPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", originalPath, err)
	}
	backupName := sanitizePath(originalPath)
	backupPath := filepath.Join(checkpointDir, BackupSubdir, backupName)
	if err := os.WriteFile(backupPath, data, info.Mode()); err != nil {
		return nil, fmt.Errorf("write backup %s: %w", backupPath, err)
	}
	return &Backup{
		OriginalPath: originalPath,
		BackupPath:   backupPath,
		Mode:         uint32(info.Mode()),
	}, nil
}

// sanitizePath converts an absolute path to a safe filename.
func sanitizePath(p string) string {
	result := make([]rune, 0, len(p))
	for _, c := range p {
		if c == '/' {
			result = append(result, '_')
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// ListCheckpoints returns all checkpoints sorted by time (newest first).
func ListCheckpoints() ([]Checkpoint, error) {
	if err := EnsureDirs(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(CheckpointDir)
	if err != nil {
		return nil, err
	}
	var cps []Checkpoint
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		metaPath := filepath.Join(CheckpointDir, e.Name(), "meta.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var cp Checkpoint
		if err := json.Unmarshal(data, &cp); err != nil {
			continue
		}
		cps = append(cps, cp)
	}
	// Sort newest first
	for i := 0; i < len(cps); i++ {
		for j := i + 1; j < len(cps); j++ {
			if cps[j].Timestamp.After(cps[i].Timestamp) {
				cps[i], cps[j] = cps[j], cps[i]
			}
		}
	}
	// Trim to max
	if len(cps) > MaxCheckpoints {
		cps = cps[:MaxCheckpoints]
	}
	return cps, nil
}

// GetCheckpoint returns a specific checkpoint by ID.
func GetCheckpoint(id string) (*Checkpoint, error) {
	metaPath := filepath.Join(CheckpointDir, id, "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("checkpoint %s not found: %w", id, err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}

// SaveScan persists a scan snapshot to disk.
func SaveScan(snap domain.Snapshot) error {
	if err := EnsureDirs(); err != nil {
		return err
	}
	record := ScanRecord{
		ID:        ScanID(),
		Timestamp: time.Now(),
		Snapshot:  snap,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(ScanDir, record.ID+".json")
	// The full Snapshot (every finding, its evidence, and description) is a
	// host audit report — treat it like the exported JSON/CSV reports
	// described in SECURITY.md and keep it owner-only.
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	cleanupOldScans()
	return nil
}

// ScanID is monotonic within a process: even if two scans land in the
// same second, the in-process counter disambiguates them so we never
// overwrite a previously-saved scan record.
func ScanID() string {
	return time.Now().Format("20060102-150405.000") + "-" + scanSeq()
}

var scanSeqMu sync.Mutex
var scanSeqCount uint64

func scanSeq() string {
	scanSeqMu.Lock()
	scanSeqCount++
	n := scanSeqCount
	scanSeqMu.Unlock()
	return strconv.FormatUint(n, 36)
}

// ListScans returns all scan records sorted by time (newest first).
func ListScans() ([]ScanRecord, error) {
	if err := EnsureDirs(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(ScanDir)
	if err != nil {
		return nil, err
	}
	var scans []ScanRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(ScanDir, e.Name()))
		if err != nil {
			continue
		}
		var s ScanRecord
		if err := json.Unmarshal(data, &s); err != nil {
			continue
		}
		scans = append(scans, s)
	}
	for i := 0; i < len(scans); i++ {
		for j := i + 1; j < len(scans); j++ {
			if scans[j].Timestamp.After(scans[i].Timestamp) {
				scans[i], scans[j] = scans[j], scans[i]
			}
		}
	}
	if len(scans) > MaxScans {
		scans = scans[:MaxScans]
	}
	return scans, nil
}

func cleanupOldScans() {
	entries, err := os.ReadDir(ScanDir)
	if err != nil {
		return
	}
	if len(entries) <= MaxScans {
		return
	}
	// Remove oldest files
	type fileInfo struct {
		name    string
		modTime time.Time
	}
	var files []fileInfo
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{name: e.Name(), modTime: info.ModTime()})
	}
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].modTime.Before(files[i].modTime) {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	for _, f := range files[MaxScans:] {
		os.Remove(filepath.Join(ScanDir, f.name))
	}
}
