package composeaudit

import (
	"errors"
	"fmt"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func ScanAll() ([]domain.Finding, error) {
	projects, err := DiscoverProjects()
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 {
		return nil, nil
	}
	var all []domain.Finding
	var errs []error
	for _, p := range projects {
		findings, err := scanProject(p)
		all = append(all, findings...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return all, errors.Join(errs...)
}

func scanProject(p Project) ([]domain.Finding, error) {
	f, err := compose.Open(p.ComposePath)
	if err != nil {
		return nil, fmt.Errorf("open compose %q: %w", p.ComposePath, err)
	}

	var findings []domain.Finding
	findings = append(findings, auditProject(f, p)...)
	findings = append(findings, detectEnvFiles(f, p.ComposePath, p.Name)...)
	return findings, nil
}
