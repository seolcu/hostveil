package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type SensitiveRule struct{}

func (r *SensitiveRule) Name() string { return "sensitive" }

var secretPatterns = []string{
	"PASSWORD", "PASS", "SECRET", "TOKEN", "API_KEY",
	"APIKEY", "ACCESS_KEY", "PRIVATE_KEY", "CREDENTIALS",
}

var defaultCredPatterns = []string{
	"admin", "password", "secret", "changeme", "test",
	"root", "guest", "default",
}

func (r *SensitiveRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	for key, val := range svc.Environment {
		lower := strings.ToLower(key)

		// Check for secrets in env vars
		isSecret := false
		for _, pat := range secretPatterns {
			if strings.Contains(lower, strings.ToLower(pat)) {
				isSecret = true
				break
			}
		}

		if isSecret && val != "" {
			// Check if it looks like a default/weak value
			valLower := strings.ToLower(val)
			isDefault := false
			for _, d := range defaultCredPatterns {
				if strings.Contains(valLower, d) {
					isDefault = true
					break
				}
			}

			if isDefault {
				findings = append(findings, domain.Finding{
					ID:          "sensitive.default_secret",
					Axis:        domain.AxisSensitiveData,
					Severity:    domain.SeverityHigh,
					Scope:       domain.ScopeService,
					Source:      domain.SourceNativeCompose,
					Subject:     name,
					Service:     name,
					Title:       "Default or weak credential detected in environment",
					Description: name + " sets " + key + " to a default or weak value.",
					WhyRisky: "Default credentials are the first thing attackers try. " +
						"They are published in documentation and easily guessable.",
					HowToFix: "Use a strong, unique value via Docker secrets or an external vault:\n" +
						"  secrets:\n    - " + strings.ToLower(key) + "\n" +
						"  environment:\n    " + key + "_FILE: \"/run/secrets/" + strings.ToLower(key) + "\"",
					Evidence:    map[string]string{"env_var": key},
					Remediation: domain.RemediationReview,
				})
			} else {
				// Inline secret (not necessarily weak)
				findings = append(findings, domain.Finding{
					ID:          "sensitive.inline_secret",
					Axis:        domain.AxisSensitiveData,
					Severity:    domain.SeverityLow,
					Scope:       domain.ScopeService,
					Source:      domain.SourceNativeCompose,
					Subject:     name,
					Service:     name,
					Title:       "Inline secret detected in environment",
					Description: name + " sets " + key + " inline in the compose file.",
					WhyRisky: "Inline secrets are visible to anyone with access to the compose file, " +
						"leak into version control, and are harder to rotate.",
					HowToFix: "Use Docker secrets instead:\n" +
						"  secrets:\n    - " + strings.ToLower(key) + "\n" +
						"  environment:\n    " + key + "_FILE: \"/run/secrets/" + strings.ToLower(key) + "\"",
					Evidence:    map[string]string{"env_var": key},
					Remediation: domain.RemediationReview,
				})
			}
		}

		// Check for env_file usage (better than inline)
	}

	// Check for env_file usage (safer than inline)
	if len(svc.EnvFile) > 0 {
		// env_file is a best practice, but only mention if no env vars are set directly
	}

	return findings
}
