package platform

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// This file holds the file operations hostveil uses on paths another account
// can shape — anything under a user's home. Plain os.ReadFile, os.Stat, and
// os.Chmod all follow symlinks, and hostveil runs as root, so on such paths
// each is a confused deputy: a user who replaces their own config file with a
// symlink to /etc/passwd turns a routine permission fix into root chmod'ing
// the password database, and one who replaces it with a FIFO parks the whole
// scan inside an open(2) that never returns.

// ReadFileNoFollow reads a regular file, refusing symlinks in the final path
// component, refusing anything that is not a regular file, never blocking on
// open, and reading at most limit bytes.
//
// O_NONBLOCK is what makes the FIFO case safe: without it, opening a FIFO for
// reading blocks until a writer appears, which for an attacker's FIFO is
// never. On a regular file the flag is meaningless and the read proceeds
// normally. The fstat check happens on the open descriptor, so there is no
// gap for the file to be swapped between the check and the read.
func ReadFileNoFollow(path string, limit int64) ([]byte, error) {
	// G304: the variable path is the point, and this function is the
	// hardened way to open one — O_NOFOLLOW refuses a symlink, O_NONBLOCK
	// refuses to hang on a FIFO, and the checks below run on the descriptor
	// rather than on the name. Flagging the safe opener while the plain
	// os.ReadFile calls it replaces go unflagged is the finding backwards.
	//nolint:gosec // G304: this is the guarded open the callers were given
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (%v)", path, fi.Mode().Type())
	}

	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return b, nil
}

// ChmodNoFollow changes a file's or directory's permission bits without ever
// following a symlink: the path is opened with O_NOFOLLOW and the mode is
// applied through the descriptor, so the bits land on the inode that was
// opened and nothing else. A symlink at path fails with ELOOP rather than
// chmod'ing its target.
func ChmodNoFollow(path string, mode os.FileMode) error {
	// G304: the variable path is the point, and this function is the
	// hardened way to open one — O_NOFOLLOW refuses a symlink, O_NONBLOCK
	// refuses to hang on a FIFO, and the checks below run on the descriptor
	// rather than on the name. Flagging the safe opener while the plain
	// os.ReadFile calls it replaces go unflagged is the finding backwards.
	//nolint:gosec // G304: this is the guarded open the callers were given
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Chmod(mode)
}
