package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

const tableFragment = `<p><strong data-counted="findings.total">0</strong> <span data-counted="findings.auto">0</span> <span data-counted="findings.review">0</span> <span data-counted="findings.manual">0</span></p>
<div class="ledger-bar-fill signal" style="--pct:0%"></div>
<div class="ledger-bar-fill warning" style="--pct:0%"></div>
<div class="ledger-bar-fill muted" style="--pct:0%"></div>
<tr><td><code>compose.ds006</code></td><td>t</td><td>x</td><td>Manual</td></tr>
<tr><td><code>compose.ds016</code></td><td>t</td><td>x</td><td>Auto</td></tr>
<tr><td><code>compose.ds012</code></td><td>t</td><td>x</td><td>Review</td></tr>
<tr><td><code>cve.unpatched-image</code></td><td>t</td><td>x</td><td>Unavailable</td></tr>
`

// Whatever the cells said, they come out as the registry says, and the
// counts and bars follow them.
func TestSyncChecksWritesTheRegistrysAnswer(t *testing.T) {
	out, tl, err := syncChecks(tableFragment, "en", fix.Default())
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]string{
		"compose.ds006":       "Auto",        // registered Auto
		"compose.ds016":       "Review",      // registered, individual-only Review
		"compose.ds012":       "Manual",      // declined
		"cve.unpatched-image": "Unavailable", // kept as written
	} {
		if !strings.Contains(out, "<code>"+id+"</code></td><td>t</td><td>x</td><td>"+want+"</td>") {
			t.Errorf("%s: want %s in\n%s", id, want, out)
		}
	}
	if tl.total != 4 || tl.auto != 1 || tl.review != 1 || tl.other != 2 {
		t.Errorf("tally = %+v", tl)
	}
	for _, s := range []string{`findings.total">4<`, `findings.auto">1<`, `findings.review">1<`, `findings.manual">2<`,
		`signal" style="--pct:25%"`, `warning" style="--pct:25%"`, `muted" style="--pct:50%"`} {
		if !strings.Contains(out, s) {
			t.Errorf("missing %s", s)
		}
	}
}

func TestPercentsAlwaysSumToAHundred(t *testing.T) {
	for _, tl := range []tally{{total: 183, auto: 75, review: 100, other: 8}, {total: 3, auto: 1, review: 1, other: 1}, {total: 7, auto: 2, review: 2, other: 3}} {
		a, r, o := tl.percents()
		if a+r+o != 100 {
			t.Errorf("%+v -> %d+%d+%d", tl, a, r, o)
		}
	}
}

func TestShownKindFollowsTheFindingDependentException(t *testing.T) {
	if k := shownKind(fix.Default(), "agent.exec-unrestricted"); k != model.RemediationReview {
		t.Errorf("agent.exec-unrestricted shown as %v", k)
	}
}

// The README block is replaced whole, and nothing outside the markers moves.
func TestSyncReadmeRewritesOnlyTheMarkedBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "README.md")
	in := "before\n\n" + countsStart + "\nold text\n" + countsEnd + "\n\nafter\n"
	if err := os.WriteFile(p, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncReadme(p, readmeCounts["en"].sentence, tally{total: 10, auto: 3, review: 4, other: 3}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	if !strings.HasPrefix(got, "before\n\n"+countsStart+"\n") || !strings.HasSuffix(got, countsEnd+"\n\nafter\n") {
		t.Errorf("text outside the markers moved:\n%s", got)
	}
	if !strings.Contains(got, "**10 findings**") || !strings.Contains(got, "**7 of them") {
		t.Errorf("counts not written:\n%s", got)
	}
	if err := os.WriteFile(p, []byte("no markers\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syncReadme(p, readmeCounts["en"].sentence, tally{}); err == nil {
		t.Error("a README without the markers must be an error, not a silent skip")
	}
}
