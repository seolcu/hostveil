package adapter

import (
	"bufio"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type LynisAdapter struct{}

func (a *LynisAdapter) Name() string { return "lynis" }

func (a *LynisAdapter) IsAvailable() bool { return IsAvailable("lynis") }

func (a *LynisAdapter) Run(_ string) ([]domain.Finding, error) {
	result := RunCommand(
		"lynis", "audit", "system",
		"--quiet", "--report-file", "/tmp/lynis-report.dat",
	)

	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}

	return parseLynisOutput(result.Stdout)
}

func parseLynisOutput(output string) ([]domain.Finding, error) {
	var findings []domain.Finding

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Parse warning/suggestion lines from Lynis
		if strings.Contains(line, "[!]") || strings.Contains(line, "[suggestion]") {
			sev := domain.SeverityMedium
			if strings.Contains(line, "[!]") {
				sev = domain.SeverityHigh
			}

			findings = append(findings, domain.Finding{
				ID:          "lynis." + hashLine(line),
				Axis:        domain.AxisHostHardening,
				Severity:    sev,
				Scope:       domain.ScopeHost,
				Source:      domain.SourceLynis,
				Subject:     "host",
				Title:       truncateText(line, 80),
				Description: line,
				WhyRisky:    "Lynis security audit identified a hardening opportunity.",
				HowToFix:    "Review the Lynis suggestion and apply the recommended hardening measure.",
				Remediation: domain.RemediationReview,
			})
		}
	}

	return findings, nil
}

func hashLine(line string) string {
	// Simple hash for reproducible IDs
	h := 0
	for _, c := range line {
		h = h*31 + int(c)
	}
	return strings.ToLower(strings.ReplaceAll(
		truncateText(strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, strings.ToLower(line)), 40),
		" ", "_"))
}
