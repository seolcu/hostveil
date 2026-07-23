package core

import (
	"fmt"
	"os"
	"syscall"
)

// preserveOwner gives tmp the same uid/gid as the file it is about to
// replace.
//
// It is separate from writeFileAtomic because it is the one piece of that
// operation that has to reach past the os package: Go exposes no portable
// way to read a file's owner, so it comes from the underlying stat, the same
// way cmd/hostveil/elevate.go reaches for syscall.Exec. hostveil builds for
// linux and darwin, both of which carry Uid/Gid here.
//
// A file whose ownership already matches needs no call, which is the normal
// case and the only one that can succeed unprivileged: chown to a different
// owner requires root, and a non-root run could not have written the file in
// the first place.
func preserveOwner(tmp *os.File, path string) error {
	fi, err := os.Stat(path)
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
