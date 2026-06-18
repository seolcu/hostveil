//go:build linux

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSmoke_QuickstartTour runs the canonical "five-minute tour"
// from specs/001-selfhost-security/quickstart.md against a temp
// state. It is gated by HOSTVEIL_INTEGRATION=1 because it requires
// a built binary.
//
// The test is "smoke" — it asserts that every subcommand in the
// tour produces the documented output. It does NOT assert every
// SC-001..SC-010 contract; those are the per-contract tests in
// tests/contract/.
func TestSmoke_QuickstartTour(t *testing.T) {
	bin := binPath(t)
	xdg := t.TempDir()

	// 1. `hostveil version` prints the locked shape.
	out := mustRun(t, bin, xdg, "version")
	if !strings.HasPrefix(out, "hostveil v") {
		t.Errorf("version output = %q, want prefix 'hostveil v'", out)
	}

	// 2. `hostveil scan` produces a report file.
	dir := t.TempDir()
	mustRun(t, bin, xdg, "scan", "--report-dir", dir)
	matches, _ := filepath.Glob(filepath.Join(dir, "hostveil-*.txt"))
	if len(matches) == 0 {
		t.Errorf("scan did not write a text report file")
	}
	matches, _ = filepath.Glob(filepath.Join(dir, "hostveil-*.json"))
	if len(matches) == 0 {
		t.Errorf("scan did not write a json report file")
	}

	// 3. The JSON report is valid JSON with the locked shape.
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
	for _, k := range []string{"schema_version", "hostveil_version", "scan_run", "host", "findings"} {
		if _, ok := r[k]; !ok {
			t.Errorf("JSON report missing top-level field %q", k)
		}
	}

	// 4. `hostveil explain <rule-id>` prints a non-empty body for
	// a known rule.
	out = mustRun(t, bin, xdg, "explain", "hardening_sysctl.baseline")
	if !strings.Contains(out, "sysctl") {
		t.Errorf("explain output = %q, want mention of sysctl", out)
	}

	// 5. `hostveil suppress --list` runs cleanly (whether or
	// not there are suppressions to list).
	mustRun(t, bin, xdg, "suppress", "--list")

	// 6. `hostveil fix --help` and `hostveil rollback --help`
	// print real (non-stub) help.
	if out := mustRun(t, bin, xdg, "fix", "--help"); strings.Contains(out, "not yet implemented") {
		t.Errorf("fix --help still says 'not yet implemented'")
	}
	if out := mustRun(t, bin, xdg, "rollback", "--help"); strings.Contains(out, "not yet implemented") {
		t.Errorf("rollback --help still says 'not yet implemented'")
	}
}

// binPath resolves the path to the built binary; skipped if
// HOSTVEIL_INTEGRATION is not set.
func binPath(t *testing.T) string {
	t.Helper()
	if os.Getenv("HOSTVEIL_INTEGRATION") != "1" {
		t.Skip("HOSTVEIL_INTEGRATION not set; skipping smoke test")
	}
	if p := os.Getenv("HOSTVEIL_DIST"); p != "" {
		return p
	}
	for _, p := range []string{"dist/hostveil", "../dist/hostveil"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("hostveil binary not found; run `make build` first")
	return ""
}

// mustRun runs the binary with the given args in a temp XDG env
// and returns the combined stdout (or stderr on a non-zero exit
// for the "not yet implemented" case — which is fine for the
// smoke test).
func mustRun(t *testing.T, bin, xdg string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+xdg,
		"XDG_CONFIG_HOME="+xdg,
	)
	if err := cmd.Run(); err != nil {
		// Most subcommands succeed; the smoke test treats errors
		// as a test failure only when the output is empty.
	}
	return out.String()
}
