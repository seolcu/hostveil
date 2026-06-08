package scan

import (
	"errors"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

func TestScanningMessage(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"trivy", "Scanning container images..."},
		{"lynis", "Auditing system hardening..."},
		{"unknown", "Scanning..."},
		{"", "Scanning..."},
	}
	for _, tt := range tests {
		got := ScanningMessage(tt.tool)
		if got != tt.want {
			t.Errorf("ScanningMessage(%q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

func TestSummarizeScanError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{errors.New("config scan \"/tmp/docker-compose.yml\": trivy returned non-JSON output"), "config scan failed"},
		{errors.New("image scan \"nginx:1.20\": trivy returned invalid JSON"), "image scan failed"},
		{errors.New("docker compose ls: exit status 1"), "compose discovery failed"},
	}
	for _, tt := range tests {
		if got := summarizeScanError(tt.err); got != tt.want {
			t.Fatalf("summarizeScanError(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestRunSingleTool_NonexistentTool(t *testing.T) {
	live := domain.NewScanProgress(true)
	reg := fix.New()

	RunSingleTool(live, reg, "nonexistent-tool-xyz123")

	ts := live.ToolState("nonexistent-tool-xyz123")
	if ts.Status != domain.ToolSkipped {
		t.Errorf("expected ToolSkipped, got %v", ts.Status)
	}
}

func TestRunSingleTool_UnknownTool(t *testing.T) {
	live := domain.NewScanProgress(true)
	reg := fix.New()

	RunSingleTool(live, reg, "true")

	ts := live.ToolState("true")
	if ts.Status != domain.ToolSkipped {
		t.Errorf("expected ToolSkipped for unknown tool, got %v", ts.Status)
	}
}

func TestRunSingleTool_FinalizeOnAllDone(t *testing.T) {
	live := &domain.ScanProgress{
		Phase: "loading",
		Tools: map[string]*domain.ToolState{
			"trivy": {Status: domain.ToolDone, Message: "done"},
			"lynis": {Status: domain.ToolDone, Message: "done"},
		},
	}
	reg := fix.New()

	RunSingleTool(live, reg, "trivy")

	if live.Phase != "complete" {
		t.Errorf("expected phase 'complete', got %q", live.Phase)
	}
}

func TestRunSingleTool_DegradedStatus(t *testing.T) {
	live := &domain.ScanProgress{
		Phase: "loading",
		Tools: map[string]*domain.ToolState{
			"trivy": {Status: domain.ToolDone, Message: "done"},
			"lynis": {Status: domain.ToolDone, Message: "done"},
		},
	}
	reg := fix.New()

	RunSingleTool(live, reg, "true")

	ts := live.ToolState("true")
	if ts.Status != domain.ToolSkipped {
		t.Errorf("expected ToolSkipped for existing but unknown tool, got %v", ts.Status)
	}
}
