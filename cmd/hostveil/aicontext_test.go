package main

import (
	"context"
	"strings"
	"testing"
)

func TestAIContextShowsNotSetByDefault(t *testing.T) {
	fixtureHost(t)
	code, out := runCmd(t, func() int {
		return cmdAIContext(context.Background(), nil)
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "(not set)") {
		t.Errorf("expected \"(not set)\", got:\n%s", out)
	}
}

func TestAIContextSetThenShowRoundTrips(t *testing.T) {
	fixtureHost(t)
	text := "a personal media server, want fast security patches more than stability"

	code, out := runCmd(t, func() int {
		return cmdAIContext(context.Background(), []string{text})
	})
	if code != 0 {
		t.Fatalf("set: exit = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, text) {
		t.Errorf("set confirmation does not echo the text:\n%s", out)
	}

	code, out = runCmd(t, func() int {
		return cmdAIContext(context.Background(), nil)
	})
	if code != 0 {
		t.Fatalf("show: exit = %d, want 0\n%s", code, out)
	}
	if strings.TrimSpace(out) != text {
		t.Errorf("show = %q, want %q", strings.TrimSpace(out), text)
	}
}

func TestAIContextClearRemovesIt(t *testing.T) {
	fixtureHost(t)
	runCmd(t, func() int { return cmdAIContext(context.Background(), []string{"something"}) })

	code, out := runCmd(t, func() int {
		return cmdAIContext(context.Background(), []string{"--clear"})
	})
	if code != 0 {
		t.Fatalf("clear: exit = %d, want 0\n%s", code, out)
	}

	code, out = runCmd(t, func() int {
		return cmdAIContext(context.Background(), nil)
	})
	if code != 0 || !strings.Contains(out, "(not set)") {
		t.Errorf("after clear, show = (code %d):\n%s", code, out)
	}
}

func TestAIContextRejectsClearWithText(t *testing.T) {
	fixtureHost(t)
	code, _ := runCmd(t, func() int {
		return cmdAIContext(context.Background(), []string{"something", "--clear"})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (usage error)", code)
	}
}
