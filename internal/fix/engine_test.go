package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestMinimalHostFix(t *testing.T) {
	findings := []domain.Finding{
		{ID: "host.ssh.root_login", Service: "host"},
		{ID: "host.firewall.no_active_firewall", Service: "host"},
	}
	plan := MinimalHostFix(findings)
	if plan == nil {
		t.Fatal("MinimalHostFix returned nil")
	}
	if len(plan.HostEdits) == 0 && len(plan.ShellCmds) == 0 {
		t.Error("expected at least some actions for known host findings")
	}
	if len(plan.Actions) == 0 {
		t.Error("expected non-empty Actions list")
	}
}

func TestMinimalHostFixEmpty(t *testing.T) {
	plan := MinimalHostFix(nil)
	if plan == nil {
		t.Fatal("MinimalHostFix(nil) returned nil")
	}
	if plan.Changed() {
		t.Error("expected empty plan for nil findings")
	}
}

func TestMinimalAdapterFix(t *testing.T) {
	findings := []domain.Finding{
		{ID: "trivy.CVE-2024-0001", Service: "nginx:latest"},
		{ID: "dockle.CIS-DI-0001", Service: "nginx:latest"},
	}
	actions := MinimalAdapterFix(findings)
	if len(actions) == 0 {
		t.Error("expected actions for known adapter findings")
	}
}

func TestMinimalAdapterFixEmpty(t *testing.T) {
	actions := MinimalAdapterFix(nil)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for nil, got %d", len(actions))
	}
}

func TestPreviewAnyFindingCompose(t *testing.T) {
	f := domain.Finding{
		ID: "test", Source: domain.SourceNativeCompose,
		Remediation: domain.RemediationAuto, Service: "test-svc",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return non-empty for compose finding")
	}
}

func TestPreviewAnyFindingHost(t *testing.T) {
	f := domain.Finding{
		ID: "host.ssh.root_login", Source: domain.SourceNativeHost,
		Remediation: domain.RemediationReview, Service: "host",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Fatal("PreviewAnyFinding returned empty for host finding")
	}
	if !strings.Contains(result, "Host Edit") && !strings.Contains(result, "Shell Command") {
		t.Error("host fix preview should contain action type")
	}
	if !strings.Contains(result, "/etc/ssh/sshd_config") {
		t.Error("host fix preview should contain file path")
	}
}

func TestPreviewAnyFindingAdapter(t *testing.T) {
	f := domain.Finding{
		ID: "trivy.CVE-2024-0001", Source: domain.SourceTrivy,
		Remediation: domain.RemediationReview, Service: "nginx:latest",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Fatal("PreviewAnyFinding returned empty for adapter finding")
	}
	if !strings.Contains(result, "nginx") {
		t.Error("adapter fix preview should contain service name")
	}
}

func TestPreviewAnyFindingHostUnknown(t *testing.T) {
	f := domain.Finding{
		ID: "nonexistent.finding", Source: domain.SourceNativeHost,
		Remediation: domain.RemediationReview,
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return message for unknown host finding")
	}
}

func TestPreviewAnyFindingAdapterUnknown(t *testing.T) {
	f := domain.Finding{
		ID: "unknown.finding", Source: domain.SourceGitleaks,
		Remediation: domain.RemediationReview,
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return message for unknown adapter finding")
	}
}

func TestNewEngine(t *testing.T) {
	e := NewEngine("/compose.yml", []domain.Finding{
		{ID: "test", Remediation: domain.RemediationAuto},
	})
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.ComposeFile != "/compose.yml" {
		t.Errorf("ComposeFile = %q, want /compose.yml", e.ComposeFile)
	}
}
