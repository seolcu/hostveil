// Package trivy discovers compose projects and runs trivy config/image scans.
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func ScanAll() ([]domain.Finding, error) {
	projects, err := discoverProjects()
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 {
		return nil, nil
	}
	var all []domain.Finding
	for _, p := range projects {
		all = append(all, scanProject(p)...)
	}
	return all, nil
}

type project struct {
	Name        string
	ComposePath string
}

type composeLSProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func discoverProjects() ([]project, error) {
	ctx, cancel := context.WithTimeout(context.Background(), domain.DockerComposeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "compose", "ls", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("docker compose ls: %w", err)
	}

	var raw []composeLSProject
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("docker compose ls parse: %w", err)
	}

	var projects []project
	for _, r := range raw {
		files := strings.Split(r.ConfigFiles, ",")
		path := strings.TrimSpace(files[0])
		if path == "" {
			continue
		}
		projects = append(projects, project{Name: r.Name, ComposePath: path})
	}
	return projects, nil
}

func scanProject(p project) []domain.Finding {
	var all []domain.Finding

	cfgs, _ := runConfig(p.ComposePath)
	for i := range cfgs {
		if cfgs[i].Metadata == nil {
			cfgs[i].Metadata = map[string]string{}
		}
		cfgs[i].Metadata["compose_path"] = p.ComposePath
		cfgs[i].Metadata["project"] = p.Name
	}
	all = append(all, cfgs...)

	images := extractImages(p.ComposePath)
	for _, img := range images {
		findings, _ := runImage(img)
		for i := range findings {
			if findings[i].Metadata == nil {
				findings[i].Metadata = map[string]string{}
			}
			findings[i].Metadata["compose_path"] = p.ComposePath
			findings[i].Metadata["project"] = p.Name
		}
		all = append(all, findings...)
	}

	all = append(all, detectEnvFiles(p.ComposePath, p.Name)...)

	return all
}

func extractImages(path string) []string {
	f, err := compose.Open(path)
	if err != nil {
		return nil
	}
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil
	}
	var images []string
	for _, svc := range svcs {
		img, _ := f.GetFieldRaw(svc, "image")
		if img != "" {
			images = append(images, img)
		}
	}
	return images
}

// ── trivy config parsing ──

type configReport struct {
	Results []struct {
		Misconfigurations []misconfig `json:"Misconfigurations"`
	} `json:"Results"`
}

type misconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

func runConfig(path string) ([]domain.Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), domain.TrivyConfigTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "trivy", "config",
		"--format", "json", "--quiet", "--no-progress", path).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy config: %w", err)
	}

	var report configReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, result := range report.Results {
		for _, m := range result.Misconfigurations {
			findings = append(findings, domain.Finding{
				ID:          "trivy." + strings.ToLower(m.ID),
				Title:       m.Title,
				Description: m.Description,
				HowToFix:    m.Resolution,
				Severity:    parseSeverity(m.Severity),
				Source:      domain.SourceTrivy,
				Remediation: domain.RemediationUnavailable,
			})
		}
	}
	return findings, nil
}

// ── trivy image parsing ──

type imageReport struct {
	Results []struct {
		Vulnerabilities []vuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

type vuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Title            string `json:"Title"`
	Severity         string `json:"Severity"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
}

func runImage(image string) ([]domain.Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), domain.TrivyImageTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--format", "json", "--quiet", "--no-progress",
		"--timeout", "5m", image).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy image: %w", err)
	}

	var report imageReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, err
	}

	var findings []domain.Finding
	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			findings = append(findings, domain.Finding{
				ID:          "trivy." + strings.ToLower(v.VulnerabilityID),
				Title:       v.Title,
				Description: v.Description,
				HowToFix:    fmt.Sprintf("Update %s to version %s or later.", v.PkgName, v.FixedVersion),
				Severity:    parseSeverity(v.Severity),
				Source:      domain.SourceTrivy,
				Service:     image,
				Remediation: domain.RemediationUnavailable,
				Evidence: map[string]string{
					"package":       v.PkgName + "@" + v.InstalledVersion,
					"fixed_version": v.FixedVersion,
					"url":           v.PrimaryURL,
				},
			})
		}
	}
	return findings, nil
}

func parseSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium
	}
}

// ── env_file detection ──

func detectEnvFiles(composePath, project string) []domain.Finding {
	f, err := compose.Open(composePath)
	if err != nil {
		return nil
	}
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil
	}
	var findings []domain.Finding
	for _, svc := range svcs {
		raw, _ := f.GetFieldRaw(svc, "env_file")
		if raw == "" {
			continue
		}
		envPath := strings.TrimSpace(raw)
		if !filepath.IsAbs(envPath) {
			envPath = filepath.Join(filepath.Dir(composePath), envPath)
		}
		findings = append(findings, domain.Finding{
			ID:          "trivy.dr004",
			Title:       "Secrets in env_file",
			Description: fmt.Sprintf("Service %q uses env_file %q which may expose secrets.", svc, envPath),
			HowToFix:    "Restrict .env permissions or migrate to Docker secrets.",
			Severity:    domain.SeverityHigh,
			Source:      domain.SourceTrivy,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata: map[string]string{
				"compose_path": composePath,
				"project":      project,
				"env_path":     envPath,
			},
		})
	}
	return findings
}


