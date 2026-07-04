package composeaudit

import (
	"errors"
	"fmt"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func ScanAll(runner domain.CommandRunner) ([]domain.Finding, error) {
	projects, err := DiscoverProjects(runner)
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
	paths := p.ComposePaths
	if len(paths) == 0 && p.ComposePath != "" {
		paths = []string{p.ComposePath}
	}

	var all []domain.Finding
	var errs []error
	seen := make(map[string]bool)
	for _, path := range paths {
		f, err := compose.Open(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("open compose %q: %w", path, err))
			continue
		}

		findings := auditProject(f, p)
		findings = append(findings, detectEnvFiles(f, path, p.Name)...)
		findings = append(findings, detectInlineSecrets(f, p)...)

		for _, finding := range findings {
			key := finding.ID + "|" + finding.Service
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, finding)
		}
	}
	return all, errors.Join(errs...)
}
