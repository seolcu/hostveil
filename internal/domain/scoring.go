package domain

import (
	"fmt"
	"strings"
)

const (
	scoreAxisVulnerabilities = "vulnerabilities"
	scoreAxisContainer       = "container_exposure"
	scoreAxisHost            = "host_hardening"
	scoreAxisSecrets         = "secrets"
)

type ScoreBreakdown struct {
	Overall uint8       `json:"overall"`
	Axes    []ScoreAxis `json:"axes"`
}

type ScoreAxis struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Score      uint8  `json:"score"`
	Penalty    int    `json:"penalty"`
	MaxPenalty int    `json:"max_penalty"`
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
}

type scoreAxisDef struct {
	id    string
	label string
	cap   int
}

var scoreAxisDefs = []scoreAxisDef{
	{scoreAxisVulnerabilities, "Vulnerabilities", 35},
	{scoreAxisContainer, "Container exposure", 30},
	{scoreAxisHost, "Host hardening", 25},
	{scoreAxisSecrets, "Secrets", 10},
}

func ScoreFindings(findings []Finding) ScoreBreakdown {
	axes := make([]ScoreAxis, len(scoreAxisDefs))
	axisIndex := make(map[string]int, len(scoreAxisDefs))
	for i, def := range scoreAxisDefs {
		axes[i] = ScoreAxis{ID: def.id, Label: def.label, Score: 100, MaxPenalty: def.cap}
		axisIndex[def.id] = i
	}

	seen := make(map[string]bool, len(findings))
	for i, f := range findings {
		if f.Fixed {
			continue
		}
		key := scoreDedupKey(f, i)
		if seen[key] {
			continue
		}
		seen[key] = true

		idx := axisIndex[scoreAxisForFinding(f)]
		axis := &axes[idx]
		axis.Penalty += severityPenalty(f.Severity)
		switch f.Severity {
		case SeverityCritical:
			axis.Critical++
		case SeverityHigh:
			axis.High++
		case SeverityMedium:
			axis.Medium++
		case SeverityLow:
			axis.Low++
		}
	}

	totalPenalty := 0
	for i := range axes {
		if axes[i].Penalty > axes[i].MaxPenalty {
			axes[i].Penalty = axes[i].MaxPenalty
		}
		axes[i].Score = axisScore(axes[i].Penalty, axes[i].MaxPenalty)
		totalPenalty += axes[i].Penalty
	}
	if totalPenalty > 100 {
		totalPenalty = 100
	}
	score := 100 - totalPenalty
	if score < 0 {
		score = 0
	}
	overall := uint8(score) //nolint:gosec // score is bounded 0-100
	return ScoreBreakdown{Overall: overall, Axes: axes}
}

func CalculateScore(findings []Finding) uint8 {
	return ScoreFindings(findings).Overall
}

// scoreAxisForFinding returns which scoring axis a finding counts
// against. Routing is by ID string prefix, not the structured Source
// field: SourceTrivy is the zero value of the Source enum (iota starts
// at 0), so an `f.Source == SourceTrivy` check would incorrectly match
// any finding that never had Source set at all. The prefix is "trivy."
// (not "trivy.cve-"): a Trivy finding's ID is not always CVE-shaped —
// some Trivy-reported vulnerabilities use a bare GHSA-style
// VulnerabilityID with no CVE ever assigned — so a narrower prefix would
// silently route those findings to the Container exposure axis instead
// of Vulnerabilities.
func scoreAxisForFinding(f Finding) string {
	id := strings.ToLower(f.ID)
	switch {
	case strings.HasPrefix(id, "trivy."):
		return scoreAxisVulnerabilities
	case f.Source == SourceLynis || strings.HasPrefix(id, "lynis."):
		return scoreAxisHost
	case id == "compose.dr004":
		return scoreAxisSecrets
	default:
		return scoreAxisContainer
	}
}

func scoreDedupKey(f Finding, index int) string {
	if f.ID == "" {
		return fmt.Sprintf("idx:%d", index)
	}
	key := f.Source.String() + "|" + strings.ToLower(f.ID)
	if f.Service != "" {
		key += "|" + f.Service
	}
	return key
}

func severityPenalty(s Severity) int {
	switch s {
	case SeverityCritical:
		return 8
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 2
	}
}

func axisScore(penalty, maxPenalty int) uint8 {
	if maxPenalty <= 0 {
		return 100
	}
	if penalty <= 0 {
		return 100
	}
	if penalty >= maxPenalty {
		return 0
	}
	s := 100 - penalty*100/maxPenalty
	if s < 0 {
		s = 0
	}
	return uint8(s) //nolint:gosec // s is bounded 0-100
}
