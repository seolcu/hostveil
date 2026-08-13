package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// Provenance verifies the release's signed build attestation, which is the
// claim worth checking: a checksum proves the bytes arrived intact, and says
// nothing about who produced them.
//
// The tooling is not a dependency this can require, so its absence is a note
// and not a failure. Its *failure* is a refusal, which is the install script's
// rule and is the asymmetry that matters: "I could not check" and "I checked
// and it did not hold" are different answers and only one of them is a reason
// to stop.
func Provenance(ctx context.Context, r platform.CommandRunner, archive string) (checked bool, err error) {
	if !platform.Has(r, "gh") {
		return false, nil
	}
	if _, err := r.Run(ctx, "gh", "attestation", "verify", archive, "--repo", Repo); err != nil {
		return true, fmt.Errorf("the build provenance for this archive could not be verified. "+
			"The checksum matched, but nothing proves it came from %s's release workflow: %w", Repo, err)
	}
	return true, nil
}

// BinaryFromArchive pulls the hostveil binary out of the release archive.
//
// It takes the entry named hostveil and nothing else. The archive is one this
// project publishes, so this is not a defence against a hostile tarball so
// much as a refusal to write anything the caller did not ask for: a path
// traversal in an archive that reached here would already mean the checksum
// and the attestation had both been defeated.
func BinaryFromArchive(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("the download is not a gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if filepath.Base(hdr.Name) != "hostveil" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		bin, err := io.ReadAll(io.LimitReader(tr, maxArchive))
		if err != nil {
			return nil, err
		}
		if len(bin) == 0 {
			return nil, fmt.Errorf("the archive's hostveil entry is empty")
		}
		return bin, nil
	}
	return nil, fmt.Errorf("the archive does not contain a hostveil binary")
}

// Replace writes the new binary over path, atomically.
//
// Beside the target and then renamed, for two reasons that are each sufficient.
// A running executable cannot be opened for writing at all — the kernel
// answers ETXTBSY — so writing through the path is not merely unwise here, it
// does not work. And a rename either happens or does not: a truncate-then-write
// that is interrupted leaves a host with a zero-length hostveil, which is the
// state in which the tool that would tell you something is wrong is the thing
// that is wrong.
//
// The mode is taken from the file being replaced rather than assumed, so a
// deployment that tightened it keeps its choice.
func Replace(path string, binary []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reading the current binary: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".hostveil-update-*")
	if err != nil {
		return fmt.Errorf("writing into %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // a no-op once the rename has succeeded

	if _, err := tmp.Write(binary); err != nil {
		_ = tmp.Close() // the write already failed; the close cannot improve on it
		return err
	}
	// Flushed before the rename, not after. A rename that publishes a file
	// whose contents are still in the page cache is the same torn write in a
	// slower disguise.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Remove deletes the binary. State is deliberately left alone; see StateNote.
func Remove(path string) error { return os.Remove(path) }

// StateNote is what to say after removing the binary.
//
// The checkpoints are backups of every file hostveil edited on this host, so
// deleting them with the program would take away the ability to undo work the
// program did — and an operator uninstalling a tool is not necessarily
// abandoning the changes it made. The installer says the same thing in the
// same words; saying it differently here would read as two different policies.
func StateNote(dir string) string {
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	return "Saved scans and rollback checkpoints are still in:\n  " + dir +
		"\nThose checkpoints are the backups of every file hostveil edited here.\n" +
		"Delete them only if you no longer need to undo any of its fixes:\n  rm -rf " + dir
}

// InstalledVersion asks the binary at path what it is, which is the only way
// to know an update took effect.
//
// It is not a formality. `apt-get install` on a package whose version dpkg
// already records is a no-op that exits 0, so an update run against a host
// whose binary was replaced by hand reported success while nothing changed:
// dpkg said 3.17.0, apt agreed there was nothing to do, and the binary on disk
// stayed where it was. Every other layer of this project refuses to claim a
// change it has not confirmed, and this is where an updater does that.
func InstalledVersion(ctx context.Context, r platform.CommandRunner, path string) (string, error) {
	out, err := r.Run(ctx, path, "version")
	if err != nil {
		return "", err
	}
	// "hostveil v3.17.0" — the last field, with the leading v left on for
	// SameVersion to deal with.
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("%s printed nothing for `version`", path)
	}
	return fields[len(fields)-1], nil
}
