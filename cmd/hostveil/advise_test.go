package main

import (
	"context"
	"strings"
	"testing"
)

func TestAdvisePrintsThePlainListingWithNoAI(t *testing.T) {
	fixtureHost(t)
	code, out := runCmd(t, func() int {
		return cmdAdvise(context.Background(), []string{"--only", "compose"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	// exposedRedis's finding, compose.ds018, is Auto-fixable and carries a
	// Benefit — it should show up in the deterministic listing even with
	// no --ai.
	if !strings.Contains(out, "Datastore") && !strings.Contains(out, "ds018") {
		t.Errorf("the exposed-redis finding is missing from advise's listing:\n%s", out)
	}
	if strings.Contains(out, "AI verdict") {
		t.Errorf("no --ai was given; the AI section should not appear:\n%s", out)
	}
}

func TestAdviseRejectsBadDomainSelection(t *testing.T) {
	fixtureHost(t)
	code, _ := runCmd(t, func() int {
		return cmdAdvise(context.Background(), []string{"--only", "compose", "--skip", "ssh"})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (usage error)", code)
	}
}
