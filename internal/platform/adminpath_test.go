package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// adminBin writes an executable of the given name into a directory that is not
// on PATH, and points adminDirs at it for the duration of the test.
func adminBin(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		t.Fatal(err)
	}
	saved := adminDirs
	adminDirs = []string{dir}
	t.Cleanup(func() { adminDirs = saved })
	return path
}

// The defect this closes, at the layer it lives in.
//
// On Debian and its derivatives /usr/sbin is not on a non-root user's PATH, and
// ufw, nft and iptables all live there. exec.LookPath therefore fails for a
// firewall that is installed and running — and the firewall domain reads a
// front-end it cannot find as one that is not installed, then reads every
// front-end missing as "no firewall is active". A real Debian 13 host scored
// 50/100 with a High finding unprivileged and 100/100 clean as root, minutes
// apart, and the High one advised installing a firewall that was already
// running.
func TestLookPathFindsAToolThatOnlyLivesInAnAdminDir(t *testing.T) {
	// A name PATH cannot possibly resolve, so a pass here can only come from
	// the admin-directory search.
	const name = "hostveil-test-fw"
	want := adminBin(t, name, 0o755)

	got, err := DefaultRunner{}.LookPath(name)
	if err != nil {
		t.Fatalf("LookPath(%q) = %v; a binary in an admin directory is installed, "+
			"and reporting it absent is what turned a running ufw into a High finding", name, err)
	}
	if got != want {
		t.Errorf("LookPath(%q) = %q, want %q", name, got, want)
	}
	if !Has(DefaultRunner{}, name) {
		t.Error("Has disagrees with LookPath; Has is what the firewall probe actually calls")
	}
}

// A file that is not executable is not a tool. Returning it would hand the
// caller a path that fails at exec, which reads as "the tool errored" — a
// coverage gap where there is really nothing installed at all.
func TestLookPathIgnoresANonExecutableFileInAnAdminDir(t *testing.T) {
	const name = "hostveil-test-notabin"
	adminBin(t, name, 0o644)

	r := DefaultRunner{}
	if got, err := r.LookPath(name); err == nil {
		t.Errorf("LookPath(%q) = %q, want an error: the file is not executable", name, got)
	}
}

// A directory of the right name is not a tool either.
func TestLookPathIgnoresADirectoryInAnAdminDir(t *testing.T) {
	const name = "hostveil-test-dir"
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
		t.Fatal(err)
	}
	saved := adminDirs
	adminDirs = []string{dir}
	t.Cleanup(func() { adminDirs = saved })

	r := DefaultRunner{}
	if got, err := r.LookPath(name); err == nil {
		t.Errorf("LookPath(%q) = %q, want an error", name, got)
	}
}

// A name carrying a separator is a path the caller chose. Resolving its
// basename under /usr/sbin would run a different program than the one named,
// which is the one outcome worse than not finding it.
func TestLookPathDoesNotRewriteAPathTheCallerGave(t *testing.T) {
	const name = "hostveil-test-explicit"
	adminBin(t, name, 0o755)

	r := DefaultRunner{}
	if got, err := r.LookPath("./" + name); err == nil {
		t.Errorf("LookPath(%q) = %q; a relative or absolute path must not be "+
			"resolved out of an admin directory", "./"+name, got)
	}
}

// PATH still wins. The admin directories are appended, so a host that
// deliberately shadows a tool earlier on PATH keeps its own answer.
func TestPathStillWinsOverTheAdminDirs(t *testing.T) {
	const name = "hostveil-test-shadowed"
	adminBin(t, name, 0o755)

	onPath := t.TempDir()
	preferred := filepath.Join(onPath, name)
	if err := os.WriteFile(preferred, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", onPath)

	got, err := DefaultRunner{}.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != preferred {
		t.Errorf("LookPath(%q) = %q, want the one on PATH at %q", name, got, preferred)
	}
}
