//go:build linux

// Package integration holds the end-to-end tests that drive
// the actual `hostveil` binary. The tests in this file are
// gated by HOSTVEIL_PERF=1 so the default CI signal stays
// clean. When the env var is set, the assertions run and
// fail on a regression. Each test corresponds to a single
// Success Criterion (SC-001, SC-007, SC-008, SC-009) from
// specs/001-selfhost-security/spec.md and is also tracked
// in docs/sc-verification.md.
package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestPerf_SC001_FullScanUnder5Min asserts SC-001: a full
// scan against the test host finishes in under 5 minutes.
// The test is gated by HOSTVEIL_PERF=1.
func TestPerf_SC001_FullScanUnder5Min(t *testing.T) {
	if os.Getenv("HOSTVEIL_PERF") != "1" {
		t.Skip("HOSTVEIL_PERF not set; skipping perf test")
	}
	bin := binPath(t)
	xdg := t.TempDir()

	start := time.Now()
	cmd := exec.Command(bin, "scan", "--report-dir", t.TempDir())
	cmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+xdg,
		"XDG_CONFIG_HOME="+xdg,
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		// exit 1 == at least one high/critical finding; that
		// is success for the perf assertion. exit 2 == scan
		// error, which we fail on.
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 2 {
				t.Fatalf("scan errored: %v\noutput=%s", err, out.String())
			}
		} else {
			t.Fatalf("scan failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Minute {
		t.Errorf("SC-001: full scan took %s, want < 5m", elapsed)
	}
	t.Logf("SC-001: full scan completed in %s", elapsed)
}

// TestPerf_SC009_AIExplainFallbackUnder1s asserts SC-009's
// 1-second fallback: when the AI provider is unreachable
// (or the binary is built with `-tags noai`), the
// explanation subcommand returns in under 1 second.
//
// In v3.0.0 the `hostveil explain` subcommand always uses
// the static explanation (the AI layer is a v3.x deliverable),
// so this test asserts the floor of SC-009 today and the
// ceiling once the AI layer is wired up.
func TestPerf_SC009_AIExplainFallbackUnder1s(t *testing.T) {
	if os.Getenv("HOSTVEIL_PERF") != "1" {
		t.Skip("HOSTVEIL_PERF not set; skipping perf test")
	}
	bin := binPath(t)
	xdg := t.TempDir()

	start := time.Now()
	cmd := exec.Command(bin, "explain", "hardening_sysctl.baseline")
	cmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+xdg,
		"XDG_CONFIG_HOME="+xdg,
	)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("explain failed: %v\noutput=%s", err, out.String())
	}
	elapsed := time.Since(start)
	if elapsed > 1*time.Second {
		t.Errorf("SC-009: explain fallback took %s, want < 1s", elapsed)
	}
	t.Logf("SC-009: explain fallback completed in %s", elapsed)
}
