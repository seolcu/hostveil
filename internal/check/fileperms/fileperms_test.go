package fileperms

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

func writeMode(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// run drives the mode rules and nothing else. OwnerUID is the account
// running the suite, so the fixtures in this file — temp files owned by
// whoever that is — are correctly owned and the ownership check stays
// silent. Without it these tests pass under root and fail under CI's
// unprivileged user, which is exactly how this was caught.
func run(t *testing.T, rules []Rule) []model.Finding {
	t.Helper()
	fs, err := (&Checker{Rules: rules, OwnerUID: os.Geteuid()}).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestOverPermissiveFileFlagged(t *testing.T) {
	// 0o644 shadow exceeds the 0o640 max (world-readable) -> flagged.
	path := writeMode(t, "shadow", 0o644)
	fs := run(t, []Rule{{Path: path, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "shadow", Desc: "d"}})
	if len(fs) != 1 || fs[0].ID != "fileperms.shadow" {
		t.Fatalf("expected fileperms.shadow, got %v", fs)
	}
	if fs[0].Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", fs[0].Severity)
	}
	if fs[0].Evidence["expected"] != "0640" {
		t.Errorf("expected evidence = %q, want 0640", fs[0].Evidence["expected"])
	}
}

func TestCorrectModeNotFlagged(t *testing.T) {
	path := writeMode(t, "shadow", 0o640)
	fs := run(t, []Rule{{Path: path, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "shadow", Desc: "d"}})
	if len(fs) != 0 {
		t.Errorf("correct-mode file should not be flagged, got %v", fs)
	}
}

func TestStricterModeNotFlagged(t *testing.T) {
	// 0o600 is stricter than the 0o640 max -> fine.
	path := writeMode(t, "shadow", 0o600)
	fs := run(t, []Rule{{Path: path, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "shadow", Desc: "d"}})
	if len(fs) != 0 {
		t.Errorf("stricter-mode file should not be flagged, got %v", fs)
	}
}

func TestMissingFileNotFlagged(t *testing.T) {
	fs := run(t, []Rule{{Path: filepath.Join(t.TempDir(), "nope"), MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "shadow", Desc: "d"}})
	if len(fs) != 0 {
		t.Errorf("missing file should not be flagged, got %v", fs)
	}
}

func TestGlobHostKeysAggregated(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"ssh_host_rsa_key", "ssh_host_ed25519_key"} {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil { // world-readable private key
			t.Fatal(err)
		}
	}
	fs := run(t, []Rule{{Path: filepath.Join(dir, "ssh_host_*_key"), Glob: true, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.hostkey", Title: "hostkey", Desc: "d"}})
	if len(fs) != 1 {
		t.Fatalf("expected one aggregated hostkey finding, got %v", fs)
	}
	if got := fs[0].Evidence["files"]; got == "" {
		t.Errorf("expected files evidence, got empty")
	}
}

func TestDefaultRulesConstructible(t *testing.T) {
	// New() must produce well-formed rules the engine will accept.
	for _, r := range New().Rules {
		if r.ID == "" || r.Title == "" {
			t.Errorf("default rule missing id/title: %+v", r)
		}
	}
}

// The checker's declared kind is half of how remediation is settled — the
// registry is the other half, and classify takes the stricter. Declaring
// Manual here would keep these Manual no matter what the registry offers.
func TestFilePermsDeclaresAutoAndCarriesPaths(t *testing.T) {
	// writeMode mints its own TempDir per call, so a glob rule needs the
	// files placed side by side here.
	dir := t.TempDir()
	a := filepath.Join(dir, "one")
	b := filepath.Join(dir, "two")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fs := run(t, []Rule{{Path: filepath.Join(dir, "*"), Glob: true, MaxMode: 0o640,
		Sev: model.SeverityHigh, ID: "fileperms.hostkey", Title: "t"}})
	if len(fs) != 1 {
		t.Fatalf("expected one aggregated finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Remediation != model.RemediationAuto {
		t.Errorf("remediation = %v, want Auto", f.Remediation)
	}
	// The machine-readable twin of "files": bare paths, joined by the shared
	// evidence separator, so a fix does not have to parse "/x (0644)" prose.
	paths := f.Evidence["paths"]
	if !strings.Contains(paths, a) || !strings.Contains(paths, b) {
		t.Errorf("paths evidence = %q, want both files", paths)
	}
	if strings.Contains(paths, "(") {
		t.Errorf("paths evidence must carry bare paths, got %q", paths)
	}
	if f.Evidence["expected"] != "0640" {
		t.Errorf("expected = %q, want 0640", f.Evidence["expected"])
	}
}

// A directory the scan cannot enter is not a directory with no host keys in
// it. filepath.Glob reports an unreadable directory as zero matches and a nil
// error, so the two arrived identically — and the one that means "I was not
// allowed to look" cleared a High-severity rule about SSH private keys being
// readable by the wrong people.
func TestAnUnreadableGlobDirectoryDegradesTheDomain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory, so the permission gap cannot be staged")
	}
	dir := filepath.Join(t.TempDir(), "ssh")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_rsa_key"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	pattern := filepath.Join(dir, "ssh_host_*_key")
	// The premise: Glob is silent about why it found nothing.
	if m, err := filepath.Glob(pattern); len(m) != 0 || err != nil {
		t.Fatalf("premise broken — Glob returned %v, %v", m, err)
	}

	_, err := (&Checker{Rules: []Rule{{
		Path: pattern, Glob: true, MaxMode: 0o640, Sev: model.SeverityHigh,
		ID: "fileperms.hostkey", Title: "host key", Desc: "d",
	}}}).Check(context.Background(), platform.Env{})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
	if !strings.Contains(partial.Reason, dir) {
		t.Errorf("the unreadable directory is missing from %q", partial.Reason)
	}
}

// The same distinction one level down: a file that exists but cannot be
// statted is a rule that did not run, not a rule that passed.
func TestAnUnstattableFileDegradesTheDomain(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root stats every file, so the permission gap cannot be staged")
	}
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "shadow")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	// The premise: the error is a denial, not an absence.
	if _, err := os.Stat(path); err == nil || os.IsNotExist(err) {
		t.Fatalf("premise broken — stat returned %v", err)
	}

	_, err := (&Checker{Rules: []Rule{{
		Path: path, MaxMode: 0o640, Sev: model.SeverityHigh,
		ID: "fileperms.shadow", Title: "shadow", Desc: "d",
	}}}).Check(context.Background(), platform.Env{})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
	if !strings.Contains(partial.Reason, path) {
		t.Errorf("the unstattable file is missing from %q", partial.Reason)
	}
}

// A file that is simply not on this host — no SSH server, no /etc/shadow — is
// nothing to judge, and must stay a clean result. Without this the fix above
// would mark every minimal host Degraded.
func TestAbsentFilesAreStillClean(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "not-here")
	_, err := (&Checker{Rules: []Rule{
		{Path: missing, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "s", Desc: "d"},
		{Path: filepath.Join(t.TempDir(), "ssh_host_*_key"), Glob: true, MaxMode: 0o640,
			Sev: model.SeverityHigh, ID: "fileperms.hostkey", Title: "h", Desc: "d"},
	}}).Check(context.Background(), platform.Env{})
	if err != nil {
		t.Errorf("a host missing these files is clean, not degraded: %v", err)
	}
}
