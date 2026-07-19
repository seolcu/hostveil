package fileperms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func run(t *testing.T, rules []Rule) []model.Finding {
	t.Helper()
	fs, err := (&Checker{Rules: rules}).Check(context.Background(), platform.Env{})
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
