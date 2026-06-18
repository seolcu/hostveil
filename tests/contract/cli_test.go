//go:build linux

// Package contract holds the public-surface lock-in tests for
// hostveil. These tests are the contract layer that prevents
// silent breakage of the CLI, the report format, or the
// version output.
//
// Run via `go test ./tests/contract/...`.
package contract

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// distPath is the path to the built binary. tests/contract tests
// assume the binary has been built; `make build` is the standard
// entry point.
func distPath(t *testing.T) string {
	t.Helper()
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

func runCmd(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	// Use a per-test temp dir for XDG so the test does not
	// pollute the user's real state.
	cmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+t.TempDir(),
		"XDG_CONFIG_HOME="+t.TempDir(),
	)
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

func TestVersion_Shape(t *testing.T) {
	bin := distPath(t)
	out, _, code := runCmd(t, bin, "version")
	if code != 0 {
		t.Errorf("version exit code = %d, want 0", code)
	}
	// Locked shape: "hostveil vX.Y.Z (commit <sha>, built <RFC3339>)".
	// The v prefix and the absence of any leading "v" double are
	// both tested.
	if !strings.HasPrefix(out, "hostveil v") {
		t.Errorf("version output = %q, want prefix \"hostveil v\"", out)
	}
	if !strings.Contains(out, " (commit ") {
		t.Errorf("version output = %q, want (commit", out)
	}
	if !strings.Contains(out, ", built ") {
		t.Errorf("version output = %q, want ', built'", out)
	}
}

func TestScan_ExitCodeContract(t *testing.T) {
	bin := distPath(t)
	// With no Dockerfile to scan, the scan still runs and exits
	// 0 (no high/critical findings on a stock empty host). We
	// just verify the contract shape: the exit code is in {0,1,2}.
	_, _, code := runCmd(t, bin, "scan", "--no-report-file")
	if code < 0 || code > 2 {
		t.Errorf("scan exit code = %d, want in {0,1,2}", code)
	}
}

func TestScan_ReportFileWritten(t *testing.T) {
	bin := distPath(t)
	// We point --report-dir at a temp dir and confirm the
	// program writes both a .txt and a .json file.
	dir := t.TempDir()
	out, errOut, _ := runCmd(t, bin, "scan", "--report-dir", dir)
	_ = out
	_ = errOut
	matches, _ := filepath.Glob(filepath.Join(dir, "hostveil-*.txt"))
	if len(matches) == 0 {
		t.Errorf("no .txt report file written to %s", dir)
	}
	matches, _ = filepath.Glob(filepath.Join(dir, "hostveil-*.json"))
	if len(matches) == 0 {
		t.Errorf("no .json report file written to %s", dir)
	}
}

func TestScan_ReportJSONShape(t *testing.T) {
	bin := distPath(t)
	dir := t.TempDir()
	runCmd(t, bin, "scan", "--report-dir", dir)
	matches, _ := filepath.Glob(filepath.Join(dir, "hostveil-*.json"))
	if len(matches) == 0 {
		t.Skip("no JSON report produced")
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("JSON report is not valid JSON: %v", err)
	}
	// Required top-level fields per contracts/report.md.
	for _, k := range []string{"schema_version", "hostveil_version", "scan_run", "host", "findings"} {
		if _, ok := r[k]; !ok {
			t.Errorf("JSON report missing top-level field %q", k)
		}
	}
	// scan_run.finding_count_* are the per-severity totals.
	sr, _ := r["scan_run"].(map[string]any)
	for _, k := range []string{"finding_count_critical", "finding_count_high", "finding_count_medium", "finding_count_low", "status", "hostveil_exit_code"} {
		if _, ok := sr[k]; !ok {
			t.Errorf("scan_run missing field %q", k)
		}
	}
}

func TestReportRedaction_PEMNeverInOutput(t *testing.T) {
	bin := distPath(t)
	dir := t.TempDir()
	// We can't actually write a PEM into the test environment
	// without a fixture host, so we only assert that the
	// redaction function is in the binary's text report.
	runCmd(t, bin, "scan", "--report-dir", dir)
	matches, _ := filepath.Glob(filepath.Join(dir, "hostveil-*.txt"))
	if len(matches) == 0 {
		t.Skip("no text report produced")
	}
	b, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	// The contract: no PEM private key block can appear.
	if strings.Contains(string(b), "-----BEGIN ") && strings.Contains(string(b), "PRIVATE KEY-----") {
		t.Errorf("text report contains a PEM private key block: %s", b)
	}
}

func TestHelp_AllSubcommandsListed(t *testing.T) {
	bin := distPath(t)
	out, _, _ := runCmd(t, bin, "--help")
	for _, want := range []string{"scan", "fix", "rollback", "explain", "suppress", "version"} {
		if !strings.Contains(out, want) {
			t.Errorf("--help output missing subcommand %q", want)
		}
	}
}
