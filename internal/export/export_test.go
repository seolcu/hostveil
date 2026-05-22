package export

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func makeTestResult() *domain.ScanResult {
	return &domain.ScanResult{
		Findings: []domain.Finding{
			{
				ID:          "test.finding",
				Title:       "Test Finding",
				Severity:    domain.SeverityHigh,
				Axis:        domain.AxisHostHardening,
				Scope:       domain.ScopeHost,
				Source:      domain.SourceNativeHost,
				Subject:     "host",
				Service:     "host",
				Description: "A test finding for export",
				WhyRisky:    "It's a test",
				HowToFix:    "Fix it",
				Remediation: domain.RemediationReview,
			},
			{
				ID:          "trivy.CVE-2024-0001",
				Title:       "Test CVE",
				Severity:    domain.SeverityCritical,
				Axis:        domain.AxisUpdateSupplyChain,
				Scope:       domain.ScopeImage,
				Source:      domain.SourceTrivy,
				Subject:     "nginx:latest",
				Service:     "nginx:latest",
				Description: "A CVE finding",
				Remediation: domain.RemediationAuto,
			},
		},
		ScoreReport: domain.ScoreReport{
			Overall: 85,
			AxisScores: map[domain.Axis]uint8{
				domain.AxisHostHardening:     80,
				domain.AxisUpdateSupplyChain: 90,
			},
			SeverityCounts: map[domain.Severity]int{
				domain.SeverityCritical: 1,
				domain.SeverityHigh:     1,
			},
		},
		Metadata: domain.ScanMetadata{
			Warnings:     []string{"test warning"},
			InfoMessages: []string{"test info"},
		},
	}
}

func TestJSON(t *testing.T) {
	r := makeTestResult()
	data, err := JSON(r, false)
	if err != nil {
		t.Fatalf("JSON() returned error: %v", err)
	}
	if !strings.Contains(data, "version") {
		t.Error("JSON output should contain 'version'")
	}
	if !strings.Contains(data, "test.finding") {
		t.Error("JSON output should contain finding ID")
	}
	if !strings.Contains(data, "overall_score") {
		t.Error("JSON output should contain overall_score")
	}
}

func TestJSONFindingsOnly(t *testing.T) {
	r := makeTestResult()
	data, err := JSON(r, true)
	if err != nil {
		t.Fatalf("JSON(findingsOnly=true) returned error: %v", err)
	}
	if !strings.Contains(data, "test.finding") {
		t.Error("JSON findings-only output should contain finding ID")
	}
	// Should be an array, not an object with version
	if !strings.HasPrefix(strings.TrimSpace(data), "[") {
		t.Error("JSON findings-only should start with array")
	}
}

func TestMarkdown(t *testing.T) {
	r := makeTestResult()
	data := Markdown(r)
	if !strings.Contains(data, "Hostveil Security Report") {
		t.Error("Markdown should contain report title")
	}
	if !strings.Contains(data, "Test Finding") {
		t.Error("Markdown should contain finding title")
	}
	if !strings.Contains(data, "85") {
		t.Error("Markdown should contain score")
	}
}

func TestHTML(t *testing.T) {
	r := makeTestResult()
	data, err := HTML(r)
	if err != nil {
		t.Fatalf("HTML() returned error: %v", err)
	}
	if !strings.Contains(data, "<html") {
		t.Error("HTML output should contain html tag")
	}
	if !strings.Contains(data, "85") {
		t.Error("HTML output should contain score")
	}
}

func TestSARIF(t *testing.T) {
	r := makeTestResult()
	data, err := SARIF(r)
	if err != nil {
		t.Fatalf("SARIF() returned error: %v", err)
	}
	if !strings.Contains(data, "sarif") {
		t.Error("SARIF output should contain 'sarif'")
	}
	if !strings.Contains(data, "hostveil") {
		t.Error("SARIF output should contain tool name")
	}
}

func TestExportEmptyFindings(t *testing.T) {
	r := &domain.ScanResult{
		ScoreReport: domain.ScoreReport{
			Overall: 100,
			AxisScores: map[domain.Axis]uint8{
				domain.AxisHostHardening: 100,
			},
		},
	}
	data, err := JSON(r, false)
	if err != nil {
		t.Fatalf("JSON(empty) returned error: %v", err)
	}
	if !strings.Contains(data, "overall_score") {
		t.Error("JSON output should contain overall_score even with no findings")
	}

	md := Markdown(r)
	if !strings.Contains(md, "Score") {
		t.Error("Markdown output should contain score even with no findings")
	}
}
