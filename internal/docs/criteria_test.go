package docs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// The published criteria pages restate constants that live in code. A number
// copied into prose is a number that drifts, and this repository's answer to
// that is to pin the copy rather than to stop making it: a user who cannot
// find the rule cannot check hostveil's work, and "read the source" is not an
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

// Every interface completes "This host is …" from the score, and until now the
// thresholds appeared nowhere a user could read. Both halves are pinned: the
// number and the sentence, because a table with the right bounds and the wrong
// wording describes a different program.
func TestTheScoringPagePublishesEveryBand(t *testing.T) {
	pages := criteriaPages(t, "scoring")
	bands := model.Bands()
	for i, b := range bands {
		// The upper bound is one below the next band up, and 100 for the top
		// one. Bands() is ordered best-first.
		lo, hi := b.Min(), uint8(100)
		if i > 0 {
			hi = bands[i-1].Min() - 1
		}
		for lang, body := range pages {
			// The range as the table writes it, e.g. "80–100" with an en dash.
			bounds := fmt.Sprintf("%d–%d", lo, hi)
			if !strings.Contains(body, bounds) {
				t.Errorf("%s scoring page does not publish the %s band's range %q", lang, b, bounds)
			}
			if !strings.Contains(body, "<code>"+b.String()+"</code>") {
				t.Errorf("%s scoring page does not name the band %q", lang, b)
			}
		}
		// The English verdict is the model's own wording; the Korean page is
		// held only to having four distinct sentences, since it is a
		// translation and not a copy.
		if !strings.Contains(pages["en"], b.Verdict()) {
			t.Errorf("the en scoring page does not carry the sentence %q that a %s host is shown", b.Verdict(), b)
		}
	}
	if n := len(model.Bands()); n != 4 {
		t.Errorf("there are now %d bands; the published table has four rows", n)
	}
}

// The verification states are what hostveil says about a fix after applying
// it, and the table had three of them. The one it was missing is the one that
// exists so hostveil does not over-claim.
func TestTheFixingPagePublishesEveryVerificationResult(t *testing.T) {
	pages := criteriaPages(t, "fixing")
	for _, v := range []model.FixVerification{
		model.VerifyGone, model.VerifyPending, model.VerifyStillPresent,
		model.VerifyUnavailable, model.VerifyNotRun,
	} {
		for lang, body := range pages {
			if !strings.Contains(body, "<code>"+v.String()+"</code>") {
				t.Errorf("%s fixing page does not publish the verification result %q, "+
					"which a user reads in --json", lang, v.String())
			}
		}
	}
}

// A user putting SARIF into GitHub code scanning meets this immediately: a
// hostveil High lands in code scanning's *critical* band, which looks like a
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
		t.Fatalf("parsing the SARIF hostveil just wrote: %v", err)
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
			// substring cannot tell hostveil's value from the one it is being
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

// "How far back can I roll back?" had no published answer. The count is the
// visible number and the duration is the actual guarantee, so both are stated
// and both are pinned.
func TestTheFixingPagePublishesCheckpointRetention(t *testing.T) {
	count, window := history.RetentionPolicy()
	pages := criteriaPages(t, "fixing")
	for lang, body := range pages {
		if !strings.Contains(body, fmt.Sprintf("<strong>%d</strong>", count)) {
			t.Errorf("%s fixing page does not publish the checkpoint cap of %d", lang, count)
		}
	}
	if window.Hours() != 1 {
		t.Fatalf("the retention window is now %v; the pages say an hour", window)
	}
	if !strings.Contains(pages["en"], "<strong>hour</strong>") {
		t.Error("the en fixing page does not publish the retention window")
	}
	if !strings.Contains(pages["ko"], "<strong>1시간</strong>") {
		t.Error("the ko fixing page does not publish the retention window")
	}
}

// The README is where most people meet the classification, and it used to name
// three of the four kinds and call the first one something the site does not.
func TestTheReadmesPublishEveryRemediationKind(t *testing.T) {
	for _, path := range []string{"README.md", "README.ko.md"} {
		body := readRepoFile(t, path)
		for _, k := range model.AllRemediationKinds() {
			if k == model.RemediationUnset {
				continue
			}
			label := k.Label()
			if path == "README.ko.md" {
				label = map[model.RemediationKind]string{
					model.RemediationAuto:        "자동 수정",
					model.RemediationReview:      "검토",
					model.RemediationManual:      "수동",
					model.RemediationUnavailable: "사용 불가",
				}[k]
			}
			if !strings.Contains(body, "**"+label+"**") {
				t.Errorf("%s does not name the %s kind as %q", path, k, label)
			}
		}
	}
}
