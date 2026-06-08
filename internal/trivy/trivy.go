// Package trivy discovers compose projects and runs trivy image scans.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/composeaudit"
	"github.com/seolcu/hostveil/internal/domain"
)

func ScanAll() ([]domain.Finding, error) {
	projects, err := composeaudit.DiscoverProjects()
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

func scanProject(p composeaudit.Project) ([]domain.Finding, error) {
	var all []domain.Finding
	var errs []error

	f, composeErr := compose.Open(p.ComposePath)
	if composeErr != nil {
		return nil, fmt.Errorf("open compose %q: %w", p.ComposePath, composeErr)
	}

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
