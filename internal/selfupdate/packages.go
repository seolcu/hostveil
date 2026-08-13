package selfupdate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/seolcu/hostveil/internal/platform"
)

// PackageAsset is the release's own package file for this origin and
// architecture, e.g. hostveil_3.17.0_linux_amd64.deb.
//
// The release publishes one per format per architecture, and installing it is
// what keeps dpkg or rpm describing the filesystem correctly. There is no apt
// or dnf repository to upgrade from, so `apt install --only-upgrade hostveil`
// would find nothing and report success — which is the failure mode this
// avoids by fetching the file the release actually has.
func PackageAsset(o Origin, version string) (string, error) {
	ext := ""
	switch o {
	case OriginDeb:
		ext = "deb"
	case OriginRPM:
		ext = "rpm"
	default:
		return "", fmt.Errorf("origin %s has no package asset", o)
	}
	return fmt.Sprintf("hostveil_%s_%s_%s.%s", version, runtime.GOOS, runtime.GOARCH, ext), nil
}

// InstallPackage hands a downloaded package file to the tool that owns it.
//
// The file is installed by path rather than by name. apt and dnf both accept
// that and both record it properly, so the package database stays true and a
// later `apt remove hostveil` still works — which is the whole reason for not
// simply writing over /usr/bin/hostveil.
func InstallPackage(ctx context.Context, r platform.CommandRunner, o Origin, path string) error {
	argv, err := installArgv(r, o, path)
	if err != nil {
		return err
	}
	if out, err := r.Run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("%s failed: %w\n%s", argv[0], err, out)
	}
	return nil
}

func installArgv(r platform.CommandRunner, o Origin, path string) ([]string, error) {
	switch o {
	case OriginDeb:
		if platform.Has(r, "apt-get") {
			// apt-get, not apt: apt prints that its CLI is not a stable
			// interface for scripts, and this is a script.
			return []string{"apt-get", "install", "-y", "--allow-downgrades", path}, nil
		}
		if platform.Has(r, "dpkg") {
			return []string{"dpkg", "-i", path}, nil
		}
		return nil, fmt.Errorf("this binary came from a .deb and neither apt-get nor dpkg is on PATH")
	case OriginRPM:
		if platform.Has(r, "dnf") {
			return []string{"dnf", "install", "-y", path}, nil
		}
		if platform.Has(r, "rpm") {
			return []string{"rpm", "-U", "--force", path}, nil
		}
		return nil, fmt.Errorf("this binary came from an .rpm and neither dnf nor rpm is on PATH")
	}
	return nil, fmt.Errorf("origin %s is not a package", o)
}

// RemovePackage uninstalls through the tool that owns the binary.
//
// By package name here, not by path: removal is a database operation and the
// file may already be gone. Unlike the install side this needs no repository,
// so it is the ordinary command and it works everywhere.
func RemovePackage(ctx context.Context, r platform.CommandRunner, o Origin) error {
	var argv []string
	switch {
	case o == OriginDeb && platform.Has(r, "apt-get"):
		argv = []string{"apt-get", "remove", "-y", "hostveil"}
	case o == OriginDeb && platform.Has(r, "dpkg"):
		argv = []string{"dpkg", "-r", "hostveil"}
	case o == OriginRPM && platform.Has(r, "dnf"):
		argv = []string{"dnf", "remove", "-y", "hostveil"}
	case o == OriginRPM && platform.Has(r, "rpm"):
		argv = []string{"rpm", "-e", "hostveil"}
	default:
		return fmt.Errorf("no package tool is available to remove this %s install", o)
	}
	if out, err := r.Run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("%s failed: %w\n%s", argv[0], err, out)
	}
	return nil
}

// Rebuild reinstalls a go-install binary from source, which is the only thing
// that corresponds to how it got there.
//
// Replacing it with a release archive would work and would be wrong: somebody
// who built from source gets a binary stamped with their build, and swapping
// it for a published one discards that without saying so.
func Rebuild(ctx context.Context, r platform.CommandRunner) error {
	if !platform.Has(r, "go") {
		return fmt.Errorf("this binary was built with `go install` and the Go toolchain is no longer on PATH, " +
			"so hostveil cannot rebuild it")
	}
	target := "github.com/" + Repo + "/cmd/hostveil@latest"
	if out, err := r.Run(ctx, "go", "install", target); err != nil {
		return fmt.Errorf("go install failed: %w\n%s", err, out)
	}
	return nil
}

// WriteTemp puts downloaded bytes somewhere a package tool can read them.
//
// Mode 0600 in a private directory: the file is about to be installed as root,
// and a world-writable staging path would let another local account swap it
// between the verification and the install.
func WriteTemp(name string, data []byte) (path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "hostveil-update-")
	if err != nil {
		return "", func() {}, err
	}
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		_ = os.RemoveAll(dir) // best effort; the caller is about to fail anyway
		return "", func() {}, err
	}
	return path, func() { _ = os.RemoveAll(dir) }, nil
}
