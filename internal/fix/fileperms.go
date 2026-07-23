package fix

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerFilePerms wires the file-permission fixes into the registry.
//
// Exact IDs, not a "fileperms.*" glob: TestEveryRegisteredFixIsValid rejects
// globs so that introducing one is a deliberate act rather than a silent
// widening of what the registry claims to fix.
func registerFilePerms(r *Registry) {
	for _, id := range []string{
		"fileperms.shadow",
		"fileperms.passwd",
		"fileperms.group",
		"fileperms.sshd-config",
		"fileperms.hostkey",
	} {
		r.Register(id, buildTightenMode)
	}
}

// tighten returns the mode with every permission bit outside mask cleared,
// and nothing else changed.
//
// It is subtractive on purpose. Assigning the rule's MaxMode outright would
// *grant* access the file did not have: /etc/shadow at 0604 violates a 0640
// rule, and setting it to 0640 would hand the shadow group a read bit it
// never had. Masking gives 0600 instead. Only ever removing bits is what
// makes this fix unambiguous enough to apply unattended.
//
// Everything outside the permission triplet is carried through untouched:
// setuid/setgid/sticky, which rebuilding from Perm() alone would silently
// clear, and the type bits — ModeDir above all. Clearing ModeDir would not
// corrupt anything (os.Chmod ignores it), but planModes compares the result
// against the full fs.FileMode, so a directory would compare unequal to
// itself forever: preview would print a phantom 0700 → 0700 row and apply
// would checkpoint and chmod a directory that was already compliant. The
// checker judged the path on its permission bits, so those are the only bits
// this fix is entitled to touch.
func tighten(current fs.FileMode, mask fs.FileMode) fs.FileMode {
	return current&^fs.ModePerm | (current.Perm() & mask)
}

func buildTightenMode(f model.Finding) (Fix, error) {
	raw := f.Evidence["paths"]
	if raw == "" {
		return Fix{}, fmt.Errorf("finding %s has no paths to tighten", f.ID)
	}
	// Split on PathListSeparator, not EvidenceSeparator: the checker writes
	// this entry for exactly this reader, and ", " occurs inside real paths.
	// No TrimSpace either — leading and trailing whitespace are part of a
	// filename, and trimming would target a different file or none at all.
	var paths []string
	for _, p := range strings.Split(raw, model.PathListSeparator) {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return Fix{}, fmt.Errorf("finding %s has no paths to tighten", f.ID)
	}

	expected := f.Evidence["expected"]
	if expected == "" {
		return Fix{}, fmt.Errorf("finding %s has no expected mode", f.ID)
	}
	// The checker formats it with %#o, so "0640" — parse as octal explicitly
	// rather than relying on the leading zero being honoured.
	n, err := strconv.ParseUint(strings.TrimPrefix(expected, "0o"), 8, 32)
	if err != nil {
		return Fix{}, fmt.Errorf("finding %s has an unparseable expected mode %q: %w", f.ID, expected, err)
	}
	mask := fs.FileMode(n).Perm()

	label := fmt.Sprintf("Tighten permissions to %#o", mask)
	if len(paths) == 1 {
		label = fmt.Sprintf("Tighten %s to %#o", paths[0], mask)
	}

	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{{
			Label: label,
			Kind:  ActionMode,
			Paths: paths,
			Mode:  func(cur fs.FileMode) fs.FileMode { return tighten(cur, mask) },
		}},
	}, nil
}
