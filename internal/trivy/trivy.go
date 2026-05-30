// Package trivy discovers compose projects and runs trivy config/image scans.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func scanProject(p project) ([]domain.Finding, error) {
	var all []domain.Finding
	var errs []error

	cfgs, err := runConfig(p.ComposePath)
	if err != nil {
		errs = append(errs, fmt.Errorf("config scan %q: %w", p.ComposePath, err))
	}
	for i := range cfgs {
		if cfgs[i].Metadata == nil {
			cfgs[i].Metadata = map[string]string{}
		}
		cfgs[i].Metadata["compose_path"] = p.ComposePath
		cfgs[i].Metadata["project"] = p.Name
	}
	all = append(all, cfgs...)

	f, composeErr := compose.Open(p.ComposePath)
	if composeErr != nil {
		errs = append(errs, fmt.Errorf("open compose %q: %w", p.ComposePath, composeErr))
	} else {
		images, imgErrs := extractImages(f)
		errs = append(errs, imgErrs...)
		for _, img := range images {
			findings, imgScanErr := runImage(img)
			if imgScanErr != nil {
				errs = append(errs, fmt.Errorf("image scan %q: %w", img, imgScanErr))
			}
			for i := range findings {
				if findings[i].Metadata == nil {
					findings[i].Metadata = map[string]string{}
				}
				findings[i].Metadata["compose_path"] = p.ComposePath
				findings[i].Metadata["project"] = p.Name
			}
			all = append(all, findings...)
		}

		envFindings, envErr := detectEnvFiles(f, p.ComposePath, p.Name)
		if envErr != nil {
			errs = append(errs, envErr)
		}
		all = append(all, envFindings...)
	}

	return all, errors.Join(errs...)
}

func extractImages(f *compose.File) ([]string, []error) {
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil, []error{err}
	}
	seen := make(map[string]bool)
	var images []string
	for _, svc := range svcs {
		img, err := f.GetFieldRaw(svc, "image")
		if err != nil {
			continue
		}
		if img != "" && !seen[img] {
			seen[img] = true
			images = append(images, img)
		}
	}
	return images, nil
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

	cmd := exec.CommandContext(ctx, "trivy", "config", "--format", "json", "--quiet", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		detail := sanitizeCommandOutput(stderr.Bytes())
		if detail == "no output" {
			detail = sanitizeCommandOutput(out)
		}
		return nil, fmt.Errorf("trivy config: %w: %s", err, detail)
	}

	var report configReport
	if err := decodeTrivyJSON(out, &report); err != nil {
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

	cmd := exec.CommandContext(ctx, "trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--format", "json", "--quiet", "--no-progress",
		"--timeout", "5m", image)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		detail := sanitizeCommandOutput(stderr.Bytes())
		return nil, fmt.Errorf("trivy image: %w: %s", err, detail)
	}
	var scanErr error
	if err != nil {
		scanErr = fmt.Errorf("trivy image partial: %w", err)
	}

	var report imageReport
	if err := decodeTrivyJSON(out, &report); err != nil {
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
	return findings, scanErr
}

func sanitizeCommandOutput(out []byte) string {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return "no output"
	}
	lines := strings.Split(msg, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Usage:") || strings.HasPrefix(line, "Aliases:") {
			continue
		}
		if strings.Contains(strings.ToLower(line), "fatal") || strings.Contains(strings.ToLower(line), "error") {
			return fitErrorLine(line)
		}
	}
	return fitErrorLine(lines[0])
}

func fitErrorLine(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 160 {
		return s
	}
	return s[:157] + "..."
}

func decodeTrivyJSON(out []byte, v any) error {
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return fmt.Errorf("trivy returned empty output")
	}
	first := trimmed[0]
	if first != '{' && first != '[' {
		return fmt.Errorf("trivy returned non-JSON output")
	}
	if err := json.Unmarshal([]byte(trimmed), v); err != nil {
		return fmt.Errorf("trivy returned invalid JSON")
	}
	return nil
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

func detectEnvFiles(f *compose.File, composePath, project string) ([]domain.Finding, error) {
	svcs, err := f.ServiceNames()
	if err != nil {
		return nil, fmt.Errorf("list services %q: %w", composePath, err)
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
	}
	return findings, nil
}
