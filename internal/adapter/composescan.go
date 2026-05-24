package adapter

import (
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type ComposeScanAdapter struct{}

func (*ComposeScanAdapter) Name() string { return "composescan" }

func (*ComposeScanAdapter) IsAvailable() bool {
	return IsAvailable("composescan")
}

func (a *ComposeScanAdapter) Run(composePath string) ([]domain.Finding, error) {
	result := RunCommand("composescan", "--json", composePath)
	if result.Err != nil && result.Stdout == "" {
		return nil, result.Err
	}
	return parseComposeScanOutput(result.Stdout, composePath)
}

type csFinding struct {
	ID          string            `json:"id"`
	Service     string            `json:"service,omitempty"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Evidence    map[string]string `json:"evidence,omitempty"`
}

func parseComposeScanOutput(stdout, composePath string) ([]domain.Finding, error) {
	var raw []csFinding
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		return nil, err
	}
	findings := make([]domain.Finding, 0, len(raw))
	for _, f := range raw {
		findings = append(findings, domain.Finding{
			ID:          f.ID,
			Axis:        csAxis(f.ID),
			Severity:    csSeverity(f.Severity),
			Scope:       domain.ScopeService,
			Source:      domain.SourceComposeScan,
			Service:     f.Service,
			Title:       f.Title,
			Description: f.Description,
			Subject:     composePath,
			Evidence:    f.Evidence,
			Remediation: csRemediation(f.ID),
		})
	}
	return findings, nil
}

func csSeverity(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium
	}
}

func csAxis(id string) domain.Axis {
	switch {
	case strings.HasPrefix(id, "security."):
		return domain.AxisExcessivePermissions
	case strings.HasPrefix(id, "sensitive."):
		return domain.AxisSensitiveData
	case strings.HasPrefix(id, "image."):
		return domain.AxisUpdateSupplyChain
	case strings.HasPrefix(id, "port."):
		return domain.AxisUnnecessaryExposure
	case strings.HasPrefix(id, "service."):
		return domain.AxisUnnecessaryExposure
	default:
		return domain.AxisUnnecessaryExposure
	}
}

func csRemediation(id string) domain.RemediationKind {
	switch {
	case strings.HasPrefix(id, "image."):
		return domain.RemediationAuto
	default:
		return domain.RemediationReview
	}
}
