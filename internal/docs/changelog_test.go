package docs

import (
	"regexp"
	"testing"
)

// The changelog is published in two languages, and the second one is the one
// that goes stale.
//
// Nothing structural stops a release being written up in English and merged,
// and there is no moment afterwards when anybody is reminded — the release is
// already out, the tag is immutable, and the missing Korean entry looks
// exactly like a release that had nothing to say. That is the same failure the
// measurement figures had: a second copy of something, with no check that the
// two agree.
//
// So the rule is mechanical. A version that appears in one changelog appears
// in the other, from 3.20.1 on, which is where the Korean file starts.
var changelogVersion = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)

// koChangelogStartsAt is the first release written up in Korean. Everything
// before it is English-only and deliberately not backfilled: inventing a
// translation of a release nobody wrote one for is worse than saying where the
// record begins, which CHANGELOG.ko.md does in its own opening lines.
const koChangelogStartsAt = "3.20.1"

func TestBothChangelogsCoverTheSameReleases(t *testing.T) {
	en := changelogVersions(t, "CHANGELOG.md")
	ko := changelogVersions(t, "CHANGELOG.ko.md")

	if len(en) == 0 || len(ko) == 0 {
		t.Fatalf("a changelog with no version headings: en=%d ko=%d", len(en), len(ko))
	}
	// Newest first, which is the order both files are written in.
	if en[0] != ko[0] {
		t.Errorf("the newest release is %s in CHANGELOG.md and %s in CHANGELOG.ko.md.\n"+
			"  A release written up in one language only ships as though it had nothing to say\n"+
			"  in the other, and there is no later moment that catches it.", en[0], ko[0])
	}

	inEN := map[string]bool{}
	for _, v := range en {
		inEN[v] = true
	}
	for _, v := range ko {
		if !inEN[v] {
			t.Errorf("CHANGELOG.ko.md has an entry for %s and CHANGELOG.md does not", v)
		}
	}

	inKO := map[string]bool{}
	for _, v := range ko {
		inKO[v] = true
	}
	for _, v := range en {
		if v == koChangelogStartsAt {
			break // everything older is English-only on purpose
		}
		if !inKO[v] {
			t.Errorf("CHANGELOG.md has an entry for %s and CHANGELOG.ko.md does not.\n"+
				"  Korean coverage starts at %s; every release from there on needs both.",
				v, koChangelogStartsAt)
		}
	}
}

func changelogVersions(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, m := range changelogVersion.FindAllStringSubmatch(readRepoFile(t, path), -1) {
		out = append(out, m[1])
	}
	return out
}
