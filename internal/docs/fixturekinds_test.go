package docs

import (
	"path/filepath"
	"regexp"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/uitest"
)

// The published screenshots print each finding's remediation beside it —
// "compose.ds016 · Manual" — so the kind in the fixture is a claim about what
// hostveil shows for that finding, the same as the ID is. It went stale the
// first time fixes were added for findings the fixture already carried: the
// pictures on the website went on saying Manual about a finding the product
// offered a button for.
//
// The checks table's Fix column is the reference because it is already held
// to the registry and to the checkers' own declarations by the sitegen and
// docs tests; holding the fixture to it holds the fixture to the product.
func TestThePublishedFixtureShowsEachFindingAsTheProductDoes(t *testing.T) {
	want := checksTableKinds(t)
	for _, f := range uitest.PublishedReport().Findings {
		kind, ok := want[f.ID]
		if !ok {
			t.Errorf("%s is in the published fixture and not in the checks table", f.ID)
			continue
		}
		if got := f.Remediation.String(); !equalFoldKind(got, kind) {
			t.Errorf("the published fixture shows %s as %s; the product shows it as %s", f.ID, got, kind)
		}
	}

	// The fixture's own promise: a finding at every remediation kind a user
	// can meet, so the pictures show what each one looks like.
	seen := map[model.RemediationKind]bool{}
	for _, f := range uitest.PublishedReport().Findings {
		seen[f.Remediation] = true
	}
	for _, k := range []model.RemediationKind{model.RemediationAuto, model.RemediationReview, model.RemediationManual} {
		if !seen[k] {
			t.Errorf("the published fixture has no %v finding, and says it shows every kind", k)
		}
	}
}

func checksTableKinds(t *testing.T) map[string]string {
	t.Helper()
	page := readRepoFile(t, filepath.Join("cmd", "sitegen", "content", "en", "docs", "checks.html"))
	rows := regexp.MustCompile(`<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>([^<]*)</td></tr>`).
		FindAllStringSubmatch(page, -1)
	out := map[string]string{}
	for _, r := range rows {
		out[r[1]] = r[2]
	}
	if len(out) < 100 {
		t.Fatalf("only %d rows parsed from the checks table; the extraction is broken", len(out))
	}
	return out
}

func equalFoldKind(a, b string) bool {
	norm := func(s string) string {
		switch s {
		case "auto", "Auto":
			return "auto"
		case "review", "Review":
			return "review"
		case "manual", "Manual":
			return "manual"
		case "unavailable", "Unavailable":
			return "unavailable"
		}
		return s
	}
	return norm(a) == norm(b)
}
