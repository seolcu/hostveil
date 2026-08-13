package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// DetectOrigin works out how the binary at path got there.
//
// The question it is really answering is "which tool should do this", and the
// default when it cannot tell is none of them. Every branch has to produce a
// definite answer before hostveil will act, because the failure it prevents is
// silent: overwriting a dpkg-owned binary leaves the package database
// describing a file that is no longer there, and the next `apt upgrade` either
// reverts the update or refuses to proceed, neither of which points back at
// hostveil.
func DetectOrigin(ctx context.Context, r platform.CommandRunner, path string) Origin {
	if path == "" {
		return OriginUnknown
	}
	// Ask the package managers first. A file can be both inside GOBIN and
	// owned by a package on a host that has done unusual things, and the
	// package answer is the one that must win.
	if ownedByDpkg(ctx, r, path) {
		return OriginDeb
	}
	if ownedByRPM(ctx, r, path) {
		return OriginRPM
	}
	if underGoBin(path) {
		return OriginGoInstall
	}
	// The install script's destination. Anything else is a copy somebody put
	// somewhere deliberately, and moving it is not this program's business.
	if filepath.Clean(path) == "/usr/bin/hostveil" {
		return OriginStandalone
	}
	return OriginUnknown
}

// ownedByDpkg asks dpkg whether it put the file there. Exit status alone is
// the answer: `dpkg -S` exits non-zero for a path no package owns.
func ownedByDpkg(ctx context.Context, r platform.CommandRunner, path string) bool {
	if !platform.Has(r, "dpkg") {
		return false
	}
	out, err := r.Run(ctx, "dpkg", "-S", path)
	return err == nil && strings.Contains(string(out), "hostveil")
}

// ownedByRPM is the same question for rpm. `rpm -qf` prints "file ... is not
// owned by any package" and exits non-zero when nothing owns it.
func ownedByRPM(ctx context.Context, r platform.CommandRunner, path string) bool {
	if !platform.Has(r, "rpm") {
		return false
	}
	out, err := r.Run(ctx, "rpm", "-qf", path)
	return err == nil && strings.Contains(string(out), "hostveil")
}

// underGoBin reports whether the path is where `go install` would have put it.
//
// GOBIN wins when it is set, then GOPATH/bin, then the default ~/go/bin. The
// environment is read rather than shelling out to `go env`, because a host
// running a release binary usually has no Go toolchain and the question is
// about a path, not about a compiler.
func underGoBin(path string) bool {
	clean := filepath.Clean(path)
	var dirs []string
	if v := os.Getenv("GOBIN"); v != "" {
		dirs = append(dirs, v)
	}
	if v := os.Getenv("GOPATH"); v != "" {
		for _, p := range filepath.SplitList(v) {
			dirs = append(dirs, filepath.Join(p, "bin"))
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if filepath.Clean(filepath.Join(d, "hostveil")) == clean {
			return true
		}
	}
	return false
}
