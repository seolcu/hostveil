package docs

import (
	"path/filepath"
	"regexp"
	"testing"
)

// The roadmap page's "how coverage has grown so far" section is the one part
// of it that is not a forecast — it is a claim about releases that already
// happened, and unlike the rest of the page it can be checked the way
// everything else published here is checked: against the code.
//
// A version marked shipped there has to actually be a release. Nothing stops
// a typo, a version that was renamed before it tagged, or an entry nobody
// updated when a release got rolled into the next one — and "we already
// shipped this" is exactly the kind of claim a reader has no way to verify
// except by trusting the page, which is the trust this repository's other
// published figures do not ask for.
var roadmapShippedVersion = regexp.MustCompile(`data-shipped="(\d+\.\d+\.\d+)"`)

func TestRoadmapShippedItemsAreRealReleases(t *testing.T) {
	changelog := map[string]bool{}
	for _, v := range changelogVersions(t, "CHANGELOG.md") {
		changelog[v] = true
	}

	checked := 0
	for _, lang := range []string{"en", "ko"} {
		page := filepath.Join("cmd", "sitegen", "content", lang, "docs", "roadmap.html")
		for _, m := range roadmapShippedVersion.FindAllStringSubmatch(readRepoFile(t, page), -1) {
			checked++
			v := m[1]
			if !changelog[v] {
				t.Errorf("%s claims %s shipped, and CHANGELOG.md has no such release.\n"+
					"  Either the version is wrong, or this page is describing a release that "+
					"never happened.", page, v)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no data-shipped entry found on either roadmap page; " +
			"the extraction is broken, or the shipped section lost its markers")
	}
}

// TestBothRoadmapsClaimTheSameShippedReleases is readmeparity_test.go's rule
// applied here: a version marked shipped in one language and silently absent
// from the other is the exact drift this file exists to catch, just moved
// from "did the number change" to "did the claim change."
func TestBothRoadmapsClaimTheSameShippedReleases(t *testing.T) {
	en := roadmapShippedVersions(t, "en")
	ko := roadmapShippedVersions(t, "ko")

	if len(en) == 0 || len(ko) == 0 {
		t.Fatalf("a roadmap page with no shipped entries: en=%d ko=%d", len(en), len(ko))
	}

	inKO := map[string]bool{}
	for _, v := range ko {
		inKO[v] = true
	}
	for _, v := range en {
		if !inKO[v] {
			t.Errorf("the English roadmap marks %s shipped and the Korean one does not", v)
		}
	}

	inEN := map[string]bool{}
	for _, v := range en {
		inEN[v] = true
	}
	for _, v := range ko {
		if !inEN[v] {
			t.Errorf("the Korean roadmap marks %s shipped and the English one does not", v)
		}
	}
}

func roadmapShippedVersions(t *testing.T, lang string) []string {
	t.Helper()
	page := filepath.Join("cmd", "sitegen", "content", lang, "docs", "roadmap.html")
	var out []string
	for _, m := range roadmapShippedVersion.FindAllStringSubmatch(readRepoFile(t, page), -1) {
		out = append(out, m[1])
	}
	return out
}
