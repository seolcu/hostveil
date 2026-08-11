package docs

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The E2E workflow reaches into `scan --json` with jq and selects domains by
// their ScanState. That couples a shell script to an encoding decided in
// internal/model, and nothing in the compiler or in CI connects the two.
//
// It has already broken once. The step named "domains that cannot run report
// Skipped, never clean" selected `.state == 3`, and #656 changed every enum to
// marshal as its name — so the selection matched no domain, the variable it
// filled was always empty, and the assertion that a skipped domain is never
// scored 100 passed on every pull request without ever looking at one. That is
// the exact failure the invariant exists to catch, hiding inside the check for
// it, and it is invisible: a vacuous jq selection is indistinguishable from a
// clean result.
//
// So the workflow's literals are pinned against what the model actually
// writes. A rename in internal/model fails here, in a Go test that runs on
// every change, rather than silently retiring the E2E assertion.
var e2eStateSelector = regexp.MustCompile(`\.state\s*==\s*("[^"]*"|[^\s)]+)`)

func TestE2ESelectsScanStatesByTheNameTheModelMarshals(t *testing.T) {
	wf := readRepoFile(t, filepath.Join(".github", "workflows", "e2e.yml"))

	matches := e2eStateSelector.FindAllStringSubmatch(withoutComments(wf), -1)
	if len(matches) == 0 {
		// Not "nothing to check": the step is how the never-score-a-skipped-
		// domain invariant is tested against a real host at all.
		t.Fatal("e2e.yml no longer selects on .state; either the step was " +
			"removed or it was rewritten, and this pin is now testing nothing")
	}

	// Every name the model can write, in the form jq compares against.
	encoded := map[string]bool{}
	for _, s := range model.AllScanStates() {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		encoded[string(b)] = true
	}

	for _, m := range matches {
		literal := m[1]
		if !encoded[literal] {
			t.Errorf("e2e.yml selects `.state == %s`, which is not how any "+
				"ScanState marshals — the selection matches no domain and the "+
				"step passes without testing anything. Valid literals: %v",
				literal, keysOf(encoded))
		}
	}
}

// TestEveryScanStateNameIsUsableInJQ guards the other half: the workflow can
// only select by name while the names stay plain strings. An ordinal, or a
// name carrying a quote or a backslash, would need escaping the jq programs in
// e2e.yml do not do.
func TestEveryScanStateNameIsUsableInJQ(t *testing.T) {
	for _, s := range model.AllScanStates() {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %v: %v", s, err)
		}
		got := string(b)
		want := `"` + s.String() + `"`
		if got != want {
			t.Errorf("ScanState %v marshals as %s, but e2e.yml writes it as %s; "+
				"the workflow's jq selections would no longer match", s, got, want)
		}
	}
}

// withoutComments drops whole-line comments, which are the same character in
// the YAML and in the shell inside it. The comment above the step explains the
// ordinal that used to be there by writing it out, and matching that would
// report the bug it documents. No line of a jq program in this workflow starts
// with a hash, so nothing under test is lost.
func withoutComments(s string) string {
	var kept []string
	for line := range strings.SplitSeq(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
