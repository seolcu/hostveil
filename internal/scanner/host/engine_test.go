package host

import (
	"testing"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine("/")
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if len(e.checks) != 9 {
		t.Errorf("expected 9 host checks, got %d", len(e.checks))
	}
}

func TestEngineScan(t *testing.T) {
	e := NewEngine("/")
	findings := e.Scan()
	// Scanning a real root filesystem may return 0 findings
	// in a minimal/container environment. The key assertion is
	// no panic and valid Finding objects.
	for _, f := range findings {
		if f.ID == "" {
			t.Error("found finding with empty ID")
		}
		if f.Axis.String() == "unknown" {
			t.Errorf("finding %s has unknown axis", f.ID)
		}
	}
}

func TestEngineCheckNames(t *testing.T) {
	names := []string{
		"ssh", "docker", "firewall", "kernel",
		"filesystem", "fim", "mac", "defenses", "updates",
	}
	e := NewEngine("/")
	for i, c := range e.checks {
		if c.Name() != names[i] {
			t.Errorf("expected check[%d].Name() = %q, got %q", i, names[i], c.Name())
		}
	}
}

func TestHostFindingRemediation(t *testing.T) {
	e := NewEngine("/")
	findings := e.Scan()
	for _, f := range findings {
		if f.Remediation.String() == "manual" {
			t.Errorf("finding %s has RemediationManual, should be RemediationReview", f.ID)
		}
	}
}
