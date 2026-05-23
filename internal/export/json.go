package export

import (
	"encoding/json"

	"github.com/seolcu/hostveil/internal/domain"
)

type jsonOutput struct {
	Version      string           `json:"version"`
	Overall      uint8            `json:"overall_score"`
	Findings     []jsonFinding    `json:"findings,omitempty"`
	Severity     map[string]int   `json:"severity_counts"`
	AxisScores   map[string]uint8 `json:"axis_scores"`
	Warnings     []string         `json:"warnings,omitempty"`
	InfoMessages []string         `json:"info_messages,omitempty"`
}

type jsonFinding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    string            `json:"severity"`
	Axis        string            `json:"axis"`
	Scope       string            `json:"scope"`
	Source      string            `json:"source"`
	Subject     string            `json:"subject"`
	Service     string            `json:"service"`
	Description string            `json:"description"`
	WhyRisky    string            `json:"why_risky"`
	HowToFix    string            `json:"how_to_fix"`
	Evidence    map[string]string `json:"evidence"`
	Remediation string            `json:"remediation"`
}

func JSON(r *domain.ScanResult, findingsOnly bool) (string, error) {
	var findings []jsonFinding
	for _, f := range r.Findings {
		findings = append(findings, jsonFinding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity.String(),
			Axis:        f.Axis.String(),
			Scope:       f.Scope.String(),
			Source:      f.Source.String(),
			Subject:     f.Subject,
			Service:     f.Service,
			Description: f.Description,
			WhyRisky:    f.WhyRisky,
			HowToFix:    f.HowToFix,
			Evidence:    f.Evidence,
			Remediation: f.Remediation.String(),
		})
	}

	if findingsOnly {
		data, err := json.MarshalIndent(findings, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	sev := make(map[string]int)
	for s, c := range r.ScoreReport.SeverityCounts {
		sev[s.String()] = c
	}

	axis := make(map[string]uint8)
	for a, s := range r.ScoreReport.AxisScores {
		axis[a.String()] = s
	}

	output := jsonOutput{
		Version:      domain.Version,
		Overall:      r.ScoreReport.Overall,
		Findings:     findings,
		Severity:     sev,
		AxisScores:   axis,
		Warnings:     r.Metadata.Warnings,
		InfoMessages: r.Metadata.InfoMessages,
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
