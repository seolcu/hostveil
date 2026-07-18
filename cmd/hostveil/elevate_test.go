package main

import "testing"

func TestNeedsRoot(t *testing.T) {
	cases := map[string]bool{
		"scan":     true,
		"tui":      true,
		"fix":      true,
		"serve":    true,
		"web":      true,
		"explain":  true,
		"rollback": true,
		"history":  true,
		"version":  false,
		"help":     false,
		"":         false,
		"bogus":    false,
	}
	for cmd, want := range cases {
		if got := needsRoot(cmd); got != want {
			t.Errorf("needsRoot(%q) = %v, want %v", cmd, got, want)
		}
	}
}
