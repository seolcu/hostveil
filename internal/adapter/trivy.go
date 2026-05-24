package adapter

import (
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type TrivyAdapter struct{}

func (a *TrivyAdapter) Name() string { return "trivy" }

func (a *TrivyAdapter) IsAvailable() bool { return IsAvailable("trivy") }

func (a *TrivyAdapter) Run(target string) ([]domain.Finding, error) {
	cf, err := compose.ParseFile(target)
	if err == nil {
		return scanCompose(cf, target)
	}
	return runTrivyImage(target)
}

func scanCompose(cf *compose.ComposeFile, path string) ([]domain.Finding, error) {
	var all []domain.Finding

	// 1. trivy config — IaC misconfiguration scan
	findings, err := runTrivyConfig(path)
	if err == nil {
		all = append(all, findings...)
	}

	// 2. trivy image — CVE scan per service image
	seen := make(map[string]bool)
	for _, svc := range cf.Services {
		if svc.Image == "" || seen[svc.Image] {
			continue
		}
		seen[svc.Image] = true
		findings, err := runTrivyImage(svc.Image)
		if err == nil {
			all = append(all, findings...)
		}
	}

	return all, nil
}

func runTrivyConfig(path string) ([]domain.Finding, error) {
	result := RunCommand(
		"trivy", "config",
		"--format", "json",
		"--quiet", "--no-progress",
		path,
	)
	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}
	return parseTrivyConfigOutput(result.Stdout, path)
}

func runTrivyImage(image string) ([]domain.Finding, error) {
	result := RunCommand(
		"trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--format", "json",
		"--quiet", "--no-progress",
		"--timeout", "5m",
		image,
	)
	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}
	return parseTrivyImageOutput(result.Stdout, image)
}

// ── Image CVE parsing ──

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
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

func parseTrivyImageOutput(output, image string) ([]domain.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, err
	}
	var findings []domain.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, domain.Finding{
				ID:          "trivy." + strings.ToLower(v.VulnerabilityID),
				Axis:        domain.AxisUpdateSupplyChain,
				Severity:    mapTrivySeverity(v.Severity),
				Scope:       domain.ScopeImage,
				Source:      domain.SourceTrivy,
				Subject:     image,
				Service:     image,
				Title:       truncateText(v.Title, 80),
				Description: v.Description,
				WhyRisky:    "Vulnerability " + v.VulnerabilityID + " affects " + v.PkgName + " (" + v.InstalledVersion + "). Fixed in " + v.FixedVersion + ".",
				HowToFix:    "Update " + v.PkgName + " to version " + v.FixedVersion + " or later. Rebuild the image with the updated base image.",
				Evidence: map[string]string{
					"vulnerability_id": v.VulnerabilityID,
					"package":          v.PkgName + "@" + v.InstalledVersion,
					"fixed_version":    v.FixedVersion,
					"severity":         v.Severity,
					"url":              v.PrimaryURL,
				},
				Remediation: domain.RemediationAuto,
			})
		}
	}
	return findings, nil
}

// ── Config misconfiguration parsing ──

type trivyConfigReport struct {
	Results []trivyConfigResult `json:"Results"`
}

type trivyConfigResult struct {
	Target           string               `json:"Target"`
	Misconfigurations []trivyMisconfig     `json:"Misconfigurations"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

func parseTrivyConfigOutput(output, path string) ([]domain.Finding, error) {
	var report trivyConfigReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, err
	}
	var findings []domain.Finding
	for _, result := range report.Results {
		for _, m := range result.Misconfigurations {
			findings = append(findings, domain.Finding{
				ID:          "trivy." + strings.ToLower(m.ID),
				Axis:        configAxis(m.ID),
				Severity:    mapTrivySeverity(m.Severity),
				Scope:       domain.ScopeService,
				Source:      domain.SourceTrivy,
				Subject:     path,
				Title:       truncateText(m.Title, 80),
				Description: m.Description,
				HowToFix:    m.Resolution,
				Evidence:    map[string]string{"misconfig_id": m.ID},
				Remediation: domain.RemediationReview,
			})
		}
	}
	return findings, nil
}

func configAxis(id string) domain.Axis {
	switch {
	case strings.Contains(id, "PRIVILEGED"), strings.Contains(id, "CAP_"),
		strings.Contains(id, "USER"), strings.Contains(id, "MOUNT"):
		return domain.AxisExcessivePermissions
	case strings.Contains(id, "NETWORK"), strings.Contains(id, "HOST_NETWORK"),
		strings.Contains(id, "PORT"), strings.Contains(id, "EXPOSURE"):
		return domain.AxisUnnecessaryExposure
	case strings.Contains(id, "SECRET"), strings.Contains(id, "SENSITIVE"):
		return domain.AxisSensitiveData
	case strings.Contains(id, "UPDATE"), strings.Contains(id, "SUPPLY"):
		return domain.AxisUpdateSupplyChain
	default:
		return domain.AxisExcessivePermissions
	}
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

func truncateText(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
