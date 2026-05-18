package adapter

import (
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type TrivyAdapter struct{}

func (a *TrivyAdapter) Name() string { return "trivy" }

func (a *TrivyAdapter) IsAvailable() bool { return IsAvailable("trivy") }

func (a *TrivyAdapter) Run(image string) ([]domain.Finding, error) {
	result := RunCommand(
		"trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--format", "json",
		"--quiet",
		"--no-progress",
		"--timeout", "5m",
		image,
	)

	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}

	return parseTrivyOutput(result.Stdout, image)
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target      string       `json:"Target"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Title            string `json:"Title"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
}

func parseTrivyOutput(output, image string) ([]domain.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			sev := mapTrivySeverity(v.Severity)

			findings = append(findings, domain.Finding{
				ID:          "trivy." + strings.ToLower(v.VulnerabilityID),
				Axis:        domain.AxisUpdateSupplyChain,
				Severity:    sev,
				Scope:       domain.ScopeImage,
				Source:      domain.SourceTrivy,
				Subject:     image,
				Service:     image,
				Title:       truncate(v.Title, 80),
				Description: v.Description,
				WhyRisky:    "Vulnerability " + v.VulnerabilityID + " affects " + v.PkgName + " (" + v.InstalledVersion + "). Fixed in " + v.FixedVersion + ".",
				HowToFix:    "Update " + v.PkgName + " to version " + v.FixedVersion + " or later. Rebuild the image with the updated base image.",
				Evidence: map[string]string{
					"vulnerability_id":  v.VulnerabilityID,
					"package":           v.PkgName + "@" + v.InstalledVersion,
					"fixed_version":     v.FixedVersion,
					"severity":          v.Severity,
					"url":               v.PrimaryURL,
				},
				Remediation: domain.RemediationAuto,
			})
		}
	}

	return findings, nil
}

func mapTrivySeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityLow
	}
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
