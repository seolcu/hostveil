package rules

import (
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type FindingText struct {
	Title       string
	Description string
	WhyRisky    string
	HowToFix    string
}

type Rule interface {
	Name() string
	Scan(service compose.Service, name string, cf *compose.ComposeFile) []domain.Finding
}

type RuleEngine struct {
	rules []Rule
}

func NewEngine() *RuleEngine {
	return &RuleEngine{
		rules: []Rule{
			&ExposureRule{},
			&PermissionsRule{},
			&RuntimeRule{},
			&SensitiveRule{},
			&UpdatesRule{},
			&NetworkRule{},
		},
	}
}

func (e *RuleEngine) Scan(cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	for name, svc := range cf.Services {
		for _, rule := range e.rules {
			findings = append(findings, rule.Scan(svc, name, cf)...)
		}
	}

	return findings
}

func newFinding(id string, axis domain.Axis, sev domain.Severity, svc string, text FindingText) domain.Finding {
	return domain.Finding{
		ID:          id,
		Axis:        axis,
		Severity:    sev,
		Scope:       domain.ScopeService,
		Source:      domain.SourceNativeCompose,
		Subject:     svc,
		Service:     svc,
		Title:       text.Title,
		Description: text.Description,
		WhyRisky:    text.WhyRisky,
		HowToFix:    text.HowToFix,
		Evidence:    make(map[string]string),
		Remediation: domain.RemediationAuto,
	}
}
