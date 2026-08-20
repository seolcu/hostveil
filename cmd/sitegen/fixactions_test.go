package main

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
)

// TestFixActionsCoversEveryRegisteredID guards the one thing generation
// cannot check about itself: that it ran to completion and said something
// about every fix it was supposed to. Whether what it says matches the
// registry is not this test's job — it cannot drift, because it is read
// from the registry at the moment this test runs the same as at the moment
// sitegen does. Checked in both languages: the Korean section is generated
// from the same registry through the same function, just with a different
// heading/kind vocabulary.
func TestFixActionsCoversEveryRegisteredID(t *testing.T) {
	for _, lang := range docLangs {
		out, err := renderFixActions(lang)
		if err != nil {
			t.Fatalf("%s: renderFixActions: %v", lang, err)
		}
		if out == "" {
			t.Fatalf("%s: renderFixActions returned nothing", lang)
		}
		for _, id := range fix.Default().Patterns() {
			if !strings.Contains(out, "<code>"+id+"</code>") {
				t.Errorf("%s: %s is registered but the fix-actions section does not mention it", lang, id)
			}
		}
	}
}

// TestFixActionsNeverPublishesTestScaffolding is the regression guard the
// doc comment on fixtest.Finding promises: a fixture path that looks like a
// test wrote it (under /tmp) reads as broken on a real docs page, not as
// illustrative. This is what would have caught it before a human had to.
func TestFixActionsNeverPublishesTestScaffolding(t *testing.T) {
	out, err := renderFixActions("en")
	if err != nil {
		t.Fatalf("renderFixActions: %v", err)
	}
	if strings.Contains(out, "/tmp/") {
		t.Error("the generated fix-actions section contains a /tmp/ path — " +
			"fixtest.Finding is supplying an evidence value that reads as test scaffolding; " +
			"see the doc comment on fixtest.Finding")
	}
}

// TestFixActionsRendersNoLiteralBackticks catches a Label or Warning string
// whose backtick-quoted command or path reached the page unconverted —
// inline() exists to turn those into <code> spans, and a literal backtick
// in the output means some text bypassed it.
func TestFixActionsRendersNoLiteralBackticks(t *testing.T) {
	out, err := renderFixActions("en")
	if err != nil {
		t.Fatalf("renderFixActions: %v", err)
	}
	if strings.Contains(out, "`") {
		t.Error("the generated fix-actions section contains a literal backtick; it should have gone through inline()")
	}
}

// TestFixColumnLinksResolveAndCoverEveryFixableRow checks the two directions
// linkFixColumnRows needs to get right on the real checks.html source for
// each language: every Auto-fix/Review row (or its Korean name) for a
// registered ID becomes a link, and every link it produces points at an id
// renderFixActions actually emitted — a stray anchor pointing at nothing
// would be a worse reading experience than the plain text it replaced. This
// is the test that would have caught the Korean page shipping the section
// but linking to it with the English word.
func TestFixColumnLinksResolveAndCoverEveryFixableRow(t *testing.T) {
	registry := fix.Default()
	for _, lang := range docLangs {
		src, err := assets.ReadFile("content/" + lang + "/docs/checks.html")
		if err != nil {
			t.Fatalf("%s: reading checks.html: %v", lang, err)
		}
		linked := linkFixColumnRows(string(src), registry, lang)

		actions, err := renderFixActions(lang)
		if err != nil {
			t.Fatalf("%s: renderFixActions: %v", lang, err)
		}

		for _, id := range registry.Patterns() {
			want := `href="#fix-` + id + `"`
			if !strings.Contains(linked, want) {
				t.Errorf("%s: %s is registered but its Fix-column cell was not linked (%s)", lang, id, want)
			}
			anchor := `id="fix-` + id + `"`
			if !strings.Contains(actions, anchor) {
				t.Errorf("%s: %s has a Fix-column link but renderFixActions emits no %s to land on", lang, id, anchor)
			}
		}
	}
}
