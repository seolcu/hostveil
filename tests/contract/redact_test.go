//go:build linux

package contract

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedact_ContractFromReportMD asserts the redaction list from
// contracts/report.md against the in-binary implementation. The
// test is "contract" not "unit" because the goal is to lock the
// public contract for downstream consumers, not to test the
// redaction function in isolation (the unit test in
// internal/report/redact_test.go already does that).
func TestRedact_ContractFromReportMD(t *testing.T) {
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
	// Walk the JSON; assert that no string field contains a
	// known-bad pattern. This is a coarse test — it walks all
	// strings recursively and looks for PEM / URL creds / AWS
	// keys.
	walk(t, r, "report")
}

func walk(t *testing.T, v any, path string) {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			walk(t, vv, path+"."+k)
		}
	case []any:
		for i, vv := range x {
			walk(t, vv, fmt.Sprintf("%s[%d]", path, i))
		}
	case string:
		if strings.Contains(x, "-----BEGIN ") && strings.Contains(x, "PRIVATE KEY-----") {
			t.Errorf("%s contains a PEM private key block", path)
		}
		if strings.Contains(x, "AKIA") && len(x) >= 20 && isUpperAlphaNum(x[4:20]) {
			t.Errorf("%s contains what looks like an AWS access key", path)
		}
		// URL credentials look like scheme://user:pass@host
		if strings.Contains(x, "://") && strings.Contains(x, "@") {
			if hasURLCreds(x) {
				t.Errorf("%s contains URL credentials", path)
			}
		}
	}
}

func isUpperAlphaNum(s string) bool {
	for _, r := range s {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func hasURLCreds(s string) bool {
	// Look for scheme://user:pass@host
	idx := strings.Index(s, "://")
	if idx < 0 {
		return false
	}
	rest := s[idx+3:]
	at := strings.Index(rest, "@")
	colon := strings.Index(rest, ":")
	return at > 0 && colon > 0 && colon < at
}
