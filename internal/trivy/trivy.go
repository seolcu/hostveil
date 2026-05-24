package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
)

func ScanAll() ([]domain.Finding, error) {
	projects, err := discoverProjects()
	if err != nil || len(projects) == 0 {
		return nil, err
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "compose", "ls", "--format", "json").Output()
	if err != nil {
		return nil, nil
	}

	var raw []composeLSProject
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, nil
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
	all = append(all, cfgs...)

	images := extractImages(p.ComposePath)
	for _, img := range images {
		findings, _ := runImage(img)
		all = append(all, findings...)
	}

	return all
}

func extractImages(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var images []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "image:") {
			img := strings.TrimSpace(trimmed[6:])
			if img != "" {
				images = append(images, img)
			}
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
				Title:       truncate(v.Title, 80),
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

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "..."
}
