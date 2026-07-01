package fix

import "testing"

// TestRegistry_HasExactEntry covers the lookup distinction that
// drives the related-finding cascade: an exact-match entry must be
// present, a pattern-only entry must NOT trigger the cascade.
//
// The Registry auto-detects patterns from glob metacharacters
// ("*?[") in the registered FindingID, so a registration like
// "compose.*" lands in r.patterns and not r.entries.
func TestRegistry_HasExactEntry(t *testing.T) {
	r := New()

	// No entries yet: every id returns false.
	for _, id := range []string{"x", "y", ""} {
		if r.HasExactEntry(id) {
			t.Errorf("HasExactEntry(%q) on empty registry = true, want false", id)
		}
	}

	// Register an exact entry.
	r.Register(&Fix{FindingID: "exact-id", Label: "t"})
	if !r.HasExactEntry("exact-id") {
		t.Error("HasExactEntry(\"exact-id\") after exact registration = false, want true")
	}

	// Register a wildcard pattern. HasExactEntry must NOT match the
	// pattern itself.
	r.Register(&Fix{FindingID: "compose.*", Label: "t"})
	if r.HasExactEntry("compose.*") {
		t.Error("HasExactEntry(\"compose.*\") = true, want false (pattern is not an exact entry)")
	}
	if r.HasExactEntry("compose.ds001") {
		t.Error("HasExactEntry(\"compose.ds001\") = true, want false (only WildcardMatch should hit)")
	}

	// Register a second exact entry and verify both work.
	r.Register(&Fix{FindingID: "another-id", Label: "t"})
	if !r.HasExactEntry("another-id") {
		t.Error("HasExactEntry(\"another-id\") = false, want true")
	}
}
