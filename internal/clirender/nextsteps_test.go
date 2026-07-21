package clirender

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func fnd(id string, sev model.Severity, rem model.RemediationKind) model.Finding {
	return model.NewFinding(id, "Title for "+id, sev, model.SourceSSH, rem,
		model.WithDescription("why it matters"),
		model.WithHowToFix("do the thing"),
	)
}

func report(fs ...model.Finding) model.Report {
	return model.Report{Findings: fs, Score: model.ScoreBreakdown{Overall: 42}}
}

// The report named a remediation kind per finding but never the command that
// acts on one, so a first-time user got a score, a list of problems, and no
// way in.
func TestReportEndsWithActionableCommands(t *testing.T) {
	out := Text(report(fnd("ssh.rootlogin", model.SeverityHigh, model.RemediationReview)), Options{})

	for _, want := range []string{"Next:", "hostveil explain <id>", "hostveil fix <id>"} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not offer %q:\n%s", want, out)
		}
	}
}

// fix --all is only worth naming when something can actually use it, and the
// count has to be the number of Auto findings, not the total.
func TestFixAllOfferedOnlyWithAutoFindings(t *testing.T) {
	withAuto := Text(report(
		fnd("ssh.maxauthtries", model.SeverityLow, model.RemediationAuto),
		fnd("ssh.x11forwarding", model.SeverityLow, model.RemediationAuto),
		fnd("firewall.inactive", model.SeverityHigh, model.RemediationManual),
	), Options{})
	if !strings.Contains(withAuto, "hostveil fix --all") {
		t.Error("fix --all not offered when Auto findings exist")
	}
	if !strings.Contains(withAuto, "2 safe fix(es)") {
		t.Errorf("count should be the Auto findings only, got:\n%s", withAuto)
	}

	noAuto := Text(report(
		fnd("firewall.inactive", model.SeverityHigh, model.RemediationManual),
		fnd("ssh.rootlogin", model.SeverityHigh, model.RemediationReview),
	), Options{})
	if strings.Contains(noAuto, "fix --all") {
		t.Errorf("fix --all offered with nothing to apply:\n%s", noAuto)
	}
}

// A clean host has nothing to act on, so the guidance would be noise.
func TestNoNextStepsOnACleanReport(t *testing.T) {
	if out := Text(report(), Options{}); strings.Contains(out, "Next:") {
		t.Errorf("clean report should not suggest next steps:\n%s", out)
	}
}

// Suggesting -v to someone who already passed it is the kind of small thing
// that makes a tool feel like it is not listening.
func TestVerboseHintOnlyWhenNotAlreadyVerbose(t *testing.T) {
	f := fnd("ssh.rootlogin", model.SeverityHigh, model.RemediationReview)
	if !strings.Contains(Text(report(f), Options{}), "hostveil scan -v") {
		t.Error("plain output should mention -v")
	}
	if strings.Contains(Text(report(f), Options{Verbose: true}), "hostveil scan -v") {
		t.Error("-v should not be suggested to someone already using it")
	}
}

// --- gaps the audit found in this package's existing coverage ---

// Every existing test rendered with Color:false, so nothing checked that the
// color path terminates its escapes. An unclosed sequence leaves the user's
// terminal stuck in whatever color the last finding used.
func TestColoredOutputResetsEveryEscape(t *testing.T) {
	out := Text(report(
		fnd("ssh.rootlogin", model.SeverityCritical, model.RemediationReview),
		fnd("ssh.maxauthtries", model.SeverityLow, model.RemediationAuto),
	), Options{Color: true, Verbose: true})

	if !strings.Contains(out, "\x1b[") {
		t.Fatal("Color:true produced no escape sequences at all")
	}
	// Not one reset per set: \x1b[0m clears every attribute at once, so
	// several sets followed by a single reset is correct and normal. What
	// must hold is that the report does not *end* with an attribute still
	// in force, which is what leaves the user's shell prompt colored.
	const reset = "\x1b[0m"
	last := strings.LastIndex(out, "\x1b[")
	if last < 0 || !strings.HasPrefix(out[last:], reset) {
		t.Errorf("output ends with an unreset color escape (%q) — the terminal would stay colored", out[last:min(last+20, len(out))])
	}
}

// Color:false must emit no escapes at all, which is what keeps piped output
// and CI logs clean.
func TestUncoloredOutputHasNoEscapes(t *testing.T) {
	out := Text(report(fnd("ssh.rootlogin", model.SeverityHigh, model.RemediationReview)), Options{Verbose: true})
	if strings.Contains(out, "\x1b[") {
		t.Errorf("uncolored output leaked an ANSI escape:\n%q", out)
	}
}

// JSON is the machine-readable contract and nothing asserted it was even
// valid JSON, let alone that it carried the fields a script would read.
func TestJSONIsValidAndCarriesTheReport(t *testing.T) {
	out, err := JSON(report(fnd("ssh.rootlogin", model.SeverityHigh, model.RemediationReview)))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if _, ok := parsed["findings"]; !ok {
		t.Errorf("no findings key in JSON output: %v", keys(parsed))
	}
	if _, ok := parsed["score"]; !ok {
		t.Errorf("no score key in JSON output: %v", keys(parsed))
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("JSON output must never contain ANSI escapes")
	}
	if strings.Contains(out, "Next:") {
		t.Error("JSON output must not carry the human-facing next-steps block")
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
