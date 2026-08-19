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
// sitegen does.
func TestFixActionsCoversEveryRegisteredID(t *testing.T) {
	out, err := renderFixActions()
	if err != nil {
		t.Fatalf("renderFixActions: %v", err)
	}
	if out == "" {
		t.Fatal("renderFixActions returned nothing")
	}
	for _, id := range fix.Default().Patterns() {
		if !strings.Contains(out, "<code>"+id+"</code>") {
			t.Errorf("%s is registered but the fix-actions section does not mention it", id)
		}
	}
}

// TestFixActionsNeverPublishesTestScaffolding is the regression guard the
// doc comment on fixtest.Finding promises: a fixture path that looks like a
// test wrote it (under /tmp) reads as broken on a real docs page, not as
// illustrative. This is what would have caught it before a human had to.
func TestFixActionsNeverPublishesTestScaffolding(t *testing.T) {
	out, err := renderFixActions()
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
	out, err := renderFixActions()
	if err != nil {
		t.Fatalf("renderFixActions: %v", err)
	}
	if strings.Contains(out, "`") {
		t.Error("the generated fix-actions section contains a literal backtick; it should have gone through inline()")
	}
}

// TestFixColumnLinksResolveAndCoverEveryFixableRow checks the two directions
// linkFixColumnRows needs to get right on the real checks.html source: every
// Auto-fix/Review row for a registered ID becomes a link, and every link it
// produces points at an id renderFixActions actually emitted — a stray
// anchor pointing at nothing would be a worse reading experience than the
// plain text it replaced.
func TestFixColumnLinksResolveAndCoverEveryFixableRow(t *testing.T) {
	registry := fix.Default()
	src, err := assets.ReadFile("content/en/docs/checks.html")
	if err != nil {
		t.Fatalf("reading checks.html: %v", err)
	}
	linked := linkFixColumnRows(string(src), registry)

	actions, err := renderFixActions()
	if err != nil {
		t.Fatalf("renderFixActions: %v", err)
	}

	for _, id := range registry.Patterns() {
		want := `href="#fix-` + id + `"`
		if !strings.Contains(linked, want) {
			t.Errorf("%s is registered but its Fix-column cell was not linked (%s)", id, want)
		}
		anchor := `id="fix-` + id + `"`
		if !strings.Contains(actions, anchor) {
			t.Errorf("%s has a Fix-column link but renderFixActions emits no %s to land on", id, anchor)
		}
	}
}
