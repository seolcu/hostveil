package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFileAtomic replaces path's contents in one step: write a temporary
// file beside it, then rename over the target.
//
// os.WriteFile truncates and then writes, so a crash or power loss between
// the two leaves a half-written or empty file. For the files hostveil edits
// that is not a cosmetic failure — a truncated /etc/ssh/sshd_config can mean
// sshd refuses to start and nobody can log in to the host to repair it. The
// checkpoint still holds the original, but reaching it requires the access
// the truncated file just took away. rename(2) is atomic within a
// filesystem, so a reader sees either the old file or the new one.
//
// The temporary lives in the target's own directory so the rename never
// crosses a filesystem boundary, and it is cleaned up on any failure.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".hostveil-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	// CreateTemp makes the file 0600; carry the original's mode across so the
	// rename does not silently tighten or loosen it.
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	// A rename replaces the inode, so the new file carries the temporary's
	// ownership rather than the original's. hostveil runs as root, so without
	// this a fix to a compose file owned by the operator's own account would
	// hand it to root and lock them out of editing their own file. Failing to
	// preserve ownership is an error, not something to do quietly.
	if err := preserveOwner(tmp, path); err != nil {
		_ = tmp.Close()
		return err
	}
	// Flush to disk before the rename. Without it the rename can land while
	// the contents are still in the page cache, which on a crash yields the
	// new name pointing at empty data — the very outcome this avoids.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsyncing the file makes its contents durable, but not the directory
	// entry created by rename. Without syncing the parent, a power loss can
	// still resurrect the old name or lose the new one after this function
	// returned success.
	//nolint:gosec // G304: dir is the selected destination's parent and is opened only to fsync it
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening %s to persist the rename: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("persisting the rename in %s: %w", dir, err)
	}
	return nil
}

// preserveOwner gives tmp the same uid/gid as the file it is about to
// replace.
//
// It is separate from WriteFileAtomic because it is the one piece of that
// operation that has to reach past the os package: Go exposes no portable
// way to read a file's owner, so it comes from the underlying stat, the same
// way cmd/hostveil/elevate.go reaches for syscall.Exec. hostveil builds for
// linux and darwin, both of which carry Uid/Gid here.
//
// A file whose ownership already matches needs no call, which is the normal
// case and the only one that can succeed unprivileged: chown to a different
// owner requires root, and a non-root run could not have written the file in
// the first place.
//
// Creating a file that does not exist yet is not an error and has no prior
// owner to carry across — that is the checkpoint store writing a fresh blob,
// and the temporary's own ownership is already the right answer.
func preserveOwner(tmp *os.File, path string) error {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s to preserve it", path)
	}
	uid, gid := int(st.Uid), int(st.Gid)

	tmpFI, err := tmp.Stat()
	if err != nil {
		return err
	}
	if tmpSt, ok := tmpFI.Sys().(*syscall.Stat_t); ok &&
		int(tmpSt.Uid) == uid && int(tmpSt.Gid) == gid {
		return nil
	}
	if err := tmp.Chown(uid, gid); err != nil {
		return fmt.Errorf("cannot preserve ownership (%d:%d) of %s: %w", uid, gid, path, err)
	}
	return nil
}
