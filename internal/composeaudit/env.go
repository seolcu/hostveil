package composeaudit

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func detectEnvFiles(f *compose.File, composePath, project string) []domain.Finding {
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil
	}
	var findings []domain.Finding
	for _, svc := range svcs {
		envFiles, err := f.GetFieldStrings(svc, "env_file")
		if err != nil {
			continue
		}
		for _, raw := range envFiles {
			envPath := strings.TrimSpace(raw)
			if envPath == "" {
				continue
			}
			if !filepath.IsAbs(envPath) {
				envPath = filepath.Join(filepath.Dir(composePath), envPath)
			}
			findings = append(findings, domain.Finding{
				ID:          "compose.dr004",
				Title:       "Secrets in env_file",
				Description: fmt.Sprintf("Service %q uses env_file %q which may expose secrets.", svc, envPath),
				HowToFix:    "Restrict .env permissions or migrate to Docker secrets.",
				Severity:    domain.SeverityHigh,
				Source:      domain.SourceCompose,
				Service:     svc,
				Remediation: domain.RemediationUnavailable,
				Metadata: map[string]string{
					"compose_path": composePath,
					"project":      project,
					"env_path":     envPath,
				},
			})
		}
	}
	return findings
}
