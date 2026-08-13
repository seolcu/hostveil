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
var afterFixesGuards = map[string][]string{
	// The CLI funnels both call sites through one helper, so the guard is
	// stated once and both inherit it.
	filepath.Join("internal", "clirender", "text.go"): {
		"!applicable || after <= score",
	},
	// The TUI states it twice because the two places are different shapes:
	// a header line that has room for words and a rail cell that does not.
	filepath.Join("internal", "ui", "tui", "frame.go"): {
		"m.report.Score.Applicable && after > sc",
	},
	filepath.Join("internal", "ui", "tui", "layoutview.go"): {
		"ax.Applicable && ax.AfterFixes > ax.Score",
	},
	// The dashboard funnels both of its call sites through one helper too.
	filepath.Join("internal", "ui", "web", "assets", "app.js"): {
		"applicable === false || typeof after !== \"number\" || after <= score",
	},
}

func TestEveryUIHidesAfterFixesTheSameWay(t *testing.T) {
	for rel, wants := range afterFixesGuards {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		src := string(b)
		for _, want := range wants {
			if !strings.Contains(src, want) {
				t.Errorf("%s no longer guards the after-fixes figure with %q.\n"+
					"Both refusals have to hold in every interface: nothing when it equals the "+
					"score, nothing when the axis is N/A.", rel, want)
			}
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
