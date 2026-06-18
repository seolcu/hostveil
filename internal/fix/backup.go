package fix

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupPath is the on-disk location of a backup. The base dir is
// taken from the store's paths.Backups; the file name is a
// timestamp + a short hash of the source path so a single source
// can be backed up multiple times without collision.
type BackupPath struct {
	BaseDir string
	Full    string
	SHA256  string
}

// CreateBackup copies src to a timestamped file under baseDir,
// computes its SHA-256, and returns the resulting BackupPath. The
// source is read once; the destination is written atomically (write
// to .tmp, then rename) to avoid leaving a half-written backup on
// disk. The destination's permissions mirror the source's.
func CreateBackup(baseDir, src string) (BackupPath, error) {
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return BackupPath{}, fmt.Errorf("create backup dir: %w", err)
	}
	in, err := os.Open(src)
	if err != nil {
		return BackupPath{}, fmt.Errorf("open source: %w", err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return BackupPath{}, fmt.Errorf("stat source: %w", err)
	}
	sum := sha256.New()
	tee := io.TeeReader(in, sum)

	// ts is the same timestamp format the report sink uses, so
	// backups and reports sort together in a directory listing.
	ts := time.Now().UTC().Format("20060102-150405")
	// We add a short hash of the source path so two sources with
	// the same basename (e.g. /etc/ssh/sshd_config and
	// /etc/nginx/nginx.conf both being backed up) don't collide.
	hash := sha256.Sum256([]byte(src))
	id := hex.EncodeToString(hash[:4])
	tmpName := fmt.Sprintf("hostveil-%s-%s.tmp", ts, id)
	finalName := fmt.Sprintf("hostveil-%s-%s", ts, id)
	tmpPath := filepath.Join(baseDir, tmpName)
	finalPath := filepath.Join(baseDir, finalName)

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fi.Mode().Perm())
	if err != nil {
		return BackupPath{}, fmt.Errorf("open temp: %w", err)
	}
	if _, err := io.Copy(out, tee); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return BackupPath{}, fmt.Errorf("copy: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return BackupPath{}, fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return BackupPath{}, fmt.Errorf("rename: %w", err)
	}
	return BackupPath{
		BaseDir: baseDir,
		Full:    finalPath,
		SHA256:  hex.EncodeToString(sum.Sum(nil)),
	}, nil
}

// RestoreBackup copies the backup at bp.Full back to dst, verifying
// the SHA-256 of the backup matches the recorded hash. If the hashes
// disagree the restore is refused — that means the backup file was
// tampered with on disk and the user's data would be at risk.
func RestoreBackup(bp BackupPath, dst string) error {
	b, err := os.ReadFile(bp.Full)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != bp.SHA256 {
		return fmt.Errorf("backup integrity check failed: %s != %s", got, bp.SHA256)
	}
	// Atomic write: write to .tmp, then rename.
	tmp := dst + ".hostveil-tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// VerifyByteIdentical compares the current contents of dst against
// the backup's recorded contents. Returns nil when the two are
// byte-identical, and a descriptive error otherwise. This is the
// SC-003 check used by the integration tests.
func VerifyByteIdentical(bp BackupPath, dst string) error {
	cur, err := os.ReadFile(dst)
	if err != nil {
		return fmt.Errorf("read current: %w", err)
	}
	back, err := os.ReadFile(bp.Full)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	if len(cur) != len(back) {
		return fmt.Errorf("length mismatch: current=%d, backup=%d", len(cur), len(back))
	}
	curSum := sha256.Sum256(cur)
	backSum := sha256.Sum256(back)
	if curSum != backSum {
		return fmt.Errorf("sha256 mismatch: current=%s, backup=%s", hex.EncodeToString(curSum[:]), hex.EncodeToString(backSum[:]))
	}
	return nil
}
