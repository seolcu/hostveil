package host

import "github.com/seolcu/hostveil/internal/domain"

type HostCheck interface {
	Name() string
	Scan(root string) []domain.Finding
}

type Engine struct {
	checks []HostCheck
}

func NewEngine(root string) *Engine {
	return &Engine{
		checks: []HostCheck{
			&SSHCheck{Root: root},
			&DockerCheck{Root: root},
			&FirewallCheck{Root: root},
			&KernelCheck{Root: root},
			&FilesystemCheck{Root: root},
			&FIMCheck{Root: root},
			&MACCheck{Root: root},
			&DefensesCheck{Root: root},
			&UpdatesCheck{Root: root},
		},
	}
}

func (e *Engine) Scan() []domain.Finding {
	var findings []domain.Finding
	for _, c := range e.checks {
		findings = append(findings, c.Scan("")...)
	}
	return findings
}

func hostFinding(id string, axis domain.Axis, sev domain.Severity, subject, title, desc, why, fix string) domain.Finding {
	return domain.Finding{
		ID:          id,
		Axis:        axis,
		Severity:    sev,
		Scope:       domain.ScopeHost,
		Source:      domain.SourceNativeHost,
		Subject:     subject,
		Title:       title,
		Description: desc,
		WhyRisky:    why,
		HowToFix:    fix,
		Evidence:    make(map[string]string),
		Remediation: domain.RemediationManual,
	}
}
