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
