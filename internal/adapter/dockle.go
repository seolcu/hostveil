package adapter

import (
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type DockleAdapter struct{}

func (a *DockleAdapter) Name() string { return "dockle" }

func (a *DockleAdapter) IsAvailable() bool { return IsAvailable("dockle") }

func (a *DockleAdapter) Run(image string) ([]domain.Finding, error) {
	result := RunCommand(
		"dockle",
		"--format", "json",
		"--exit-code", "1",
		image,
	)

	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}

	return parseDockleOutput(result.Stdout, image)
}

type dockleReport struct {
	Summary dockleSummary `json:"summary"`
	Details []dockleDetail `json:"details"`
}

type dockleSummary struct {
	Fatal int `json:"fatal"`
	Warn  int `json:"warn"`
	Info  int `json:"info"`
	Pass  int `json:"pass"`
}

type dockleDetail struct {
	Code    string `json:"code"`
	Title   string `json:"title"`
	Level   string `json:"level"`
	Alerts  []string `json:"alerts"`
}

func parseDockleOutput(output, image string) ([]domain.Finding, error) {
	if strings.TrimSpace(output) == "" {
		return nil, nil
	}

	var report dockleReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, d := range report.Details {
		sev := domain.SeverityMedium
		switch d.Level {
		case "FATAL":
			sev = domain.SeverityCritical
		case "WARN":
			sev = domain.SeverityMedium
		case "INFO":
			sev = domain.SeverityLow
		}

		evidence := make(map[string]string)
		if len(d.Alerts) > 0 {
			evidence["alerts"] = strings.Join(d.Alerts, "; ")
		}

		findings = append(findings, domain.Finding{
			ID:          "dockle." + d.Code,
			Axis:        domain.AxisExcessivePermissions,
			Severity:    sev,
			Scope:       domain.ScopeImage,
			Source:      domain.SourceDockle,
			Subject:     image,
			Service:     image,
			Title:       d.Title,
			Description: "Dockle check " + d.Code + ": " + d.Title,
			WhyRisky:    "Docker image best practice violation detected by Dockle.",
			HowToFix:    "Review the Dockle finding and follow the recommended fix for code " + d.Code + ". See https://github.com/goodwithtech/dockle",
			Evidence:    evidence,
			Remediation: domain.RemediationManual,
		})
	}

	return findings, nil
}
