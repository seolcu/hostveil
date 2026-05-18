package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type NetworkRule struct{}

func (r *NetworkRule) Name() string { return "network" }

func (r *NetworkRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	// Rule: using default bridge network
	if cf.Networks == nil || len(cf.Networks) == 0 {
		findings = append(findings, domain.Finding{
			ID:       "network.default_bridge_used",
			Axis:     domain.AxisUnnecessaryExposure,
			Severity: domain.SeverityLow,
			Scope:    domain.ScopeProject,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Stack relies on the default bridge network",
			Description: "The compose file does not define a custom network. " +
				"Services communicate over the default bridge.",
			WhyRisky: "The default bridge network lacks DNS-based service discovery " +
				"and automatic container isolation. User-defined networks are preferred.",
			HowToFix: "Define a custom network:\n" +
				"  networks:\n    internal:\n      driver: bridge\n" +
				"  services:\n    " + name + ":\n      networks:\n        - internal",
			Evidence:    map[string]string{"network": "default bridge"},
			Remediation: domain.RemediationAuto,
		})
	}

	// Rule: host network mode
	if strings.EqualFold(svc.NetworkMode, "host") {
		findings = append(findings, domain.Finding{
			ID:       "network.host_mode",
			Axis:     domain.AxisUnnecessaryExposure,
			Severity: domain.SeverityHigh,
			Scope:    domain.ScopeService,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Container uses host network mode",
			Description: name + " uses network_mode: host, " +
				"sharing the host's network stack directly.",
			WhyRisky: "Host network mode bypasses Docker network isolation. " +
				"A compromised container can listen on any host port and " +
				"intercept host network traffic.",
			HowToFix: "Remove host network mode and use port mapping instead:\n" +
				"  ports:\n    - \"8080:8080\"",
			Evidence:    map[string]string{"network_mode": "host"},
			Remediation: domain.RemediationManual,
		})
	}

	return findings
}
