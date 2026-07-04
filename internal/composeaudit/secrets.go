package composeaudit

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

var secretKeyPattern = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key|auth[_-]?key|credential|access[_-]?key)`)

var weakSecretValues = map[string]bool{
	"password": true, "changeme": true, "secret": true, "admin": true,
	"123456": true, "test": true, "default": true,
}

// detectInlineSecrets flags hardcoded secrets in inline environment variables.
func detectInlineSecrets(f *compose.File, project Project) []domain.Finding {
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil
	}
	var findings []domain.Finding
	for _, svc := range svcs {
		for key, val := range f.GetEnvironment(svc) {
			if !looksLikeSecret(key, val) {
				continue
			}
			findings = append(findings, domain.Finding{
				ID:          "compose.dr005",
				Title:       "Hardcoded secret in environment",
				Description: fmt.Sprintf("Service %q sets %q inline in environment. Secrets in compose files are visible to anyone with file access and often end up in version control.", svc, key),
				HowToFix:    "Move the value to a .env file (with restrictive permissions), use ${VAR} interpolation, or migrate to Docker secrets.",
				Severity:    domain.SeverityHigh,
				Source:      domain.SourceCompose,
				Service:     svc,
				Remediation: domain.RemediationUnavailable,
				Evidence: map[string]string{
					"env_key": key,
				},
				Metadata: composeMeta(project, svc),
			})
		}
	}
	return findings
}

func looksLikeSecret(key, val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}
	if strings.HasPrefix(val, "${") {
		return false
	}
	if !secretKeyPattern.MatchString(key) {
		return false
	}
	if weakSecretValues[strings.ToLower(val)] {
		return true
	}
	if len(val) >= 8 && !strings.Contains(val, " ") {
		return true
	}
	return secretKeyPattern.MatchString(val)
}
