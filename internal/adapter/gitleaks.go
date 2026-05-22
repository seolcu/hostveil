package adapter

import (
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type GitleaksAdapter struct{}

func (a *GitleaksAdapter) Name() string { return "gitleaks" }

func (a *GitleaksAdapter) IsAvailable() bool { return IsAvailable("gitleaks") }

func (a *GitleaksAdapter) Run(path string) ([]domain.Finding, error) {
	result := RunCommand(
		"gitleaks", "detect",
		"--source", path,
		"--no-git",
		"--format", "json",
		"--exit-code", "0",
		"-v",
	)

	if result.Stdout == "" {
		return nil, nil
	}

	return parseGitleaksOutput(result.Stdout, path)
}

type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	Secret      string `json:"Secret"`
	Severity    string `json:"Severity"`
	StartLine   int    `json:"StartLine"`
}

func parseGitleaksOutput(output, path string) ([]domain.Finding, error) {
	var leaks []gitleaksFinding
	if err := json.Unmarshal([]byte(output), &leaks); err != nil {
		// Might be NDJSON (one JSON per line)
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var f gitleaksFinding
			if err := json.Unmarshal([]byte(line), &f); err == nil {
				leaks = append(leaks, f)
			}
		}
	}

	var findings []domain.Finding
	for _, l := range leaks {
		sev := domain.SeverityMedium
		switch strings.ToUpper(l.Severity) {
		case "HIGH":
			sev = domain.SeverityHigh
		case "MEDIUM":
			sev = domain.SeverityMedium
		case "LOW":
			sev = domain.SeverityLow
		}

		evidence := map[string]string{
			"file": l.File,
			"line": itoa(l.StartLine),
		}

		findings = append(findings, domain.Finding{
			ID:          "gitleaks." + l.RuleID,
			Axis:        domain.AxisSensitiveData,
			Severity:    sev,
			Scope:       domain.ScopeProject,
			Source:      domain.SourceGitleaks,
			Subject:     path,
			Title:       l.Description,
			Description: "Secret leak detected by Gitleaks in " + l.File + ":" + itoa(l.StartLine),
			WhyRisky:    "Hardcoded secrets in source code can be discovered in CI logs, version control history, and backups.",
			HowToFix:    "Remove the secret from source code, rotate the credential, and use environment variables or a secrets manager.",
			Evidence:    evidence,
			Remediation: domain.RemediationReview,
		})
	}

	return findings, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte("0123456789")
	var buf [10]byte
	i := len(buf)
	for n >= 10 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	i--
	buf[i] = digits[n]
	return string(buf[i:])
}
