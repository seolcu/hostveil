package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The score and the headroom are two numbers about one host, and three
// interfaces draw them. Each owns its own formatting — a terminal cell, a
// lipgloss style, a DOM node — so there is nothing a compiler can hold them
// to. What has to agree is not the formatting but the two refusals:
//
//   - nothing where the figure equals the score, because an arrow pointing at
//     the number it starts from says the fixes are worth nothing, and on a
//     well-kept host that is most rows;
//   - nothing where the axis is N/A, because a number beside a domain nobody
//     looked at is a claim about a domain nobody looked at.
//
// This is the same shape of check as the Degraded flag's: a rule that lives in
// prose until one renderer forgets it. It reads the sources rather than
// rendering, because two of the three cannot be rendered here — the dashboard
// is JavaScript and SARIF is a machine format with its own answer.
// The Go renderers all call model.ScoreAxis.Headroom and
// model.ScoreAxis.ValueText now, so the compiler holds them together and
// there is nothing here to check. The dashboard is the one copy that cannot
// call either — it is JavaScript reading /api/result — so it is the one this
// reads.
//
// That is the point of the shrinking. This file used to grep four sources for
// the same guard, which is a test that fails when somebody rewrites a
// condition into an equivalent one and passes when they get the logic wrong
// in the same words. One irreducible copy is worth grepping for; four are a
// sign the rule is in the wrong place.
var dashboardRules = map[string]string{
	"the headroom is hidden when it would say nothing": `applicable === false || typeof after !== "number" || after <= score`,
	"a degraded axis keeps its marker":                 "`${ax.score}~`",
	"an axis that did not run says so":                 `if (!ax.applicable) return "N/A"`,
}

func TestTheDashboardKeepsTheRulesItCannotCallIntoGoFor(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "ui", "web", "assets", "app.js"))
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	src := string(b)
	for what, want := range dashboardRules {
		if !strings.Contains(src, want) {
			t.Errorf("app.js no longer states that %s (looked for %s).\n"+
				"The Go interfaces get this from model.ScoreAxis; this file is the copy "+
				"that cannot, so it is the copy that has to be read.", what, want)
		}
	}
}

// SARIF is the exception, and it is worth pinning as one so nobody
// "fixes" it into agreeing with the three UIs. A property bag is read by a
// machine that can compare two numbers itself, and a key that appears only
// sometimes is harder to consume than one that is occasionally equal to its
// neighbour.
func TestSARIFPublishesAfterFixesUnconditionally(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "clirender", "sarif.go"))
	if err != nil {
		t.Fatalf("read sarif.go: %v", err)
	}
	src := string(b)
	for _, want := range []string{`"after_fixes": ax.AfterFixes`, `"scoreAfterFixes": r.Score.AfterFixes`} {
		if !strings.Contains(src, want) {
			t.Errorf("SARIF no longer carries %s", want)
		}
	}
	// And it must not have grown a condition around them.
	if regexp.MustCompile(`if[^\n]*AfterFixes[^\n]*\{`).MatchString(src) {
		t.Error("SARIF now emits the after-fixes figure conditionally; a property bag should not hide a key")
	}
}

// Both language editions have to explain it, or the Korean reader gets a
// number on screen that the page beside it never mentions.
func TestBothScoringPagesExplainAfterFixes(t *testing.T) {
	for _, lang := range []string{"en", "ko"} {
		p := filepath.Join(repoRoot(t), "cmd", "sitegen", "content", lang, "docs", "scoring.html")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("read %s: %v", p, err)
			continue
		}
		if !strings.Contains(string(b), `id="after-fixes"`) {
			t.Errorf("%s/scoring.html does not document the after-fixes figure", lang)
		}
	}
}
