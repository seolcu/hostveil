package platform

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openParentBeneath(root, target string) (int, string, error) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return -1, "", fmt.Errorf("%s is not a file beneath %s", target, root)
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	fd, err := unix.Open(filepath.Clean(root), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, "", openErr
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

// openBeneath opens target relative to a directory descriptor for root. The
// root itself may be a legitimate symlink (a relocated home directory), but
// every component below it is opened with O_NOFOLLOW. Once root is open,
// renaming any component in the pathname cannot redirect this walk elsewhere.
func openBeneath(root, target string, finalFlags int) (*os.File, error) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("%s is not a file beneath %s", target, root)
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	fd, err := unix.Open(filepath.Clean(root), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	final, err := unix.Openat(fd, parts[len(parts)-1], finalFlags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = unix.Close(fd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(final), target), nil
}

// ReadFileBeneath is ReadFileNoFollow extended to every component below
// root. It is used for paths controlled by the account being audited while
// hostveil is running as root.
func ReadFileBeneath(root, target string, limit int64) ([]byte, error) {
	f, err := openBeneath(root, target, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (%v)", target, fi.Mode().Type())
	}
	return readLimited(f, target, limit)
}

// ChmodBeneath changes a regular file or directory reached without following
// any symlink below root.
func ChmodBeneath(root, target string, mode os.FileMode) error {
	f, err := openBeneath(root, target, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return fmt.Errorf("%s: not a regular file or directory (%v)", target, fi.Mode().Type())
	}
	return f.Chmod(mode)
}

// StatBeneath stats a path through the descriptor-rooted walk.
func StatBeneath(root, target string) (os.FileInfo, error) {
	f, err := openBeneath(root, target, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Stat()
}

// WriteFileAtomicBeneath replaces target through a parent directory opened
// beneath root. expected is the content the caller based its transform on;
// a different live value is an external edit and aborts the rename.
func WriteFileAtomicBeneath(root, target string, data []byte, mode os.FileMode, expected []byte, creating bool) error {
	parent, base, err := openParentBeneath(root, target)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()

	var prior unix.Stat_t
	statErr := unix.Fstatat(parent, base, &prior, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case creating && statErr == nil:
		return fmt.Errorf("%s appeared after it was scanned; re-scan before fixing", target)
	case creating && !errors.Is(statErr, unix.ENOENT):
		return statErr
	case !creating && statErr != nil:
		return statErr
	case !creating && prior.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%s is no longer a regular file; re-scan before fixing", target)
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmpName := "." + base + ".hostveil-" + hex.EncodeToString(suffix[:])
	fd, err := unix.Openat(parent, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	tmp := os.NewFile(uintptr(fd), tmpName)
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = unix.Unlinkat(parent, tmpName, 0)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if !creating {
		if err := tmp.Chown(int(prior.Uid), int(prior.Gid)); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if creating {
		if err := unix.Fstatat(parent, base, &prior, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return fmt.Errorf("%s appeared after it was scanned; re-scan before fixing", target)
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
	} else {
		live, err := unix.Openat(parent, base, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		liveFile := os.NewFile(uintptr(live), target)
		current, readErr := readLimited(liveFile, target, int64(len(expected)))
		_ = liveFile.Close()
		if readErr != nil || !bytes.Equal(current, expected) {
			return fmt.Errorf("%s changed after it was scanned; re-scan before fixing", target)
		}
	}
	if err := unix.Renameat(parent, tmpName, parent, base); err != nil {
		return err
	}
	cleanup = false
	if err := unix.Fsync(parent); err != nil {
		return fmt.Errorf("persisting the rename in %s: %w", filepath.Dir(target), err)
	}
	return nil
}

// RemoveBeneath removes the final name through a verified parent directory.
func RemoveBeneath(root, target string) error {
	parent, base, err := openParentBeneath(root, target)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	if err := unix.Unlinkat(parent, base, 0); err != nil {
		return err
	}
	return unix.Fsync(parent)
}
