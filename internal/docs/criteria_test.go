package docs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/model"
)

// The published criteria pages restate constants that live in code. A number
// copied into prose is a number that drifts, and this repository's answer to
// that is to pin the copy rather than to stop making it: a user who cannot
// find the rule cannot check Hostveil's work, and "read the source" is not an
// answer for a tool that asks to be trusted with root.
//
// Only the values that were not already pinned are here. cmd/sitegen/docs_test.go
// already holds the axis caps, the severity chips, the finding table and the
// en/ko parity, and duplicating it would be a second place to update.

func criteriaPages(t *testing.T, slug string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, lang := range []string{"en", "ko"} {
		out[lang] = readRepoFile(t, fmt.Sprintf("cmd/sitegen/content/%s/docs/%s.html", lang, slug))
	}
	return out
}

// A user putting SARIF into GitHub code scanning meets this immediately: a
// Hostveil High lands in code scanning's *critical* band, which looks like a
// bug until you read why.
func TestTheCLIPagePublishesTheSARIFMapping(t *testing.T) {
	// Read the mapping out of a real export rather than out of a list written
	// here. A table that agrees with a second copy of the same numbers agrees
	// with nothing.
	// The security-severity rides on the *rule*, and rules are deduplicated by
	// finding ID, so each severity needs an ID of its own.
	ids := map[model.Severity]string{
		model.SeverityHigh: "ssh.rootlogin", model.SeverityMedium: "ssh.maxauthtries",
		model.SeverityLow: "ssh.x11forwarding",
	}
	var findings []model.Finding
	for _, sev := range model.AllSeverities() {
		findings = append(findings, model.NewFinding(
			ids[sev], "t", sev, model.SourceSSH, model.RemediationManual))
	}
	out, err := clirender.SARIF(model.Report{Findings: findings}, "test")
	if err != nil {
		t.Fatalf("rendering SARIF: %v", err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string            `json:"id"`
						Properties map[string]string `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("parsing the SARIF Hostveil just wrote: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != len(findings) {
		t.Fatalf("the export carried %d runs and %d results, want 1 and %d",
			len(doc.Runs), len(doc.Runs[0].Results), len(findings))
	}
	sevOf := map[string]string{}
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		sevOf[r.ID] = r.Properties["security-severity"]
	}

	pages := criteriaPages(t, "cli")
	for _, res := range doc.Runs[0].Results {
		want := []string{"<code>" + res.Level + "</code>"}
		if sev := sevOf[res.RuleID]; sev != "" {
			// In a cell, not anywhere on the page: the prose beside the table
			// names GitHub's own bucket thresholds (9.0, 7.0, 4.0), so a bare
			// substring cannot tell Hostveil's value from the one it is being
			// compared against.
			want = append(want, "<td>"+sev+"</td>")
		} else {
			t.Errorf("%s carries no security-severity, which is what code scanning ranks by", res.RuleID)
		}
		for _, w := range want {
			for lang, body := range pages {
				if !strings.Contains(body, w) {
					t.Errorf("%s cli page does not publish %q, which the SARIF export actually emits", lang, w)
				}
			}
		}
	}
}
