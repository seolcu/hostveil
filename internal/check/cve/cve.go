// Package cve implements the optional CVE checker backed by Trivy. It is
// the one domain that may be absent: when Trivy is not installed the
// checker skips cleanly (a first-class Skipped state, not an error), and
// scoring renormalizes so the host is neither penalized nor given a false
// perfect vulnerability score.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker scans container images for known vulnerabilities via Trivy.
type Checker struct{}

// New returns a CVE checker.
func New() *Checker { return &Checker{} }

// Source identifies the CVE domain.
func (*Checker) Source() model.Source { return model.SourceCVE }

// Available requires both Trivy (the scanner) and Docker (to enumerate the
// images to scan). Missing either yields a clean skip.
func (*Checker) Available(_ context.Context, env platform.Env) (bool, string) {
	if !platform.Has(env.Runner, "trivy") {
		return false, "Trivy not installed — CVE scan skipped (install it to enable image vulnerability scanning)"
	}
	if !platform.Has(env.Runner, "docker") {
		return false, "Docker not installed — no images to scan"
	}
	return true, ""
}

// Check enumerates compose images and scans each with Trivy.
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	projects, err := compose.Discover(ctx, env.Runner)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	scanned := map[string]bool{}
	for _, p := range projects {
		for _, svc := range p.Services {
			if svc.Image == "" || scanned[svc.Image] {
				continue
			}
			scanned[svc.Image] = true
			fs, err := scanImage(ctx, env.Runner, svc.Image, svc.Name)
			if err != nil {
				// One unscannable image should not fail the whole domain.
				continue
			}
			findings = append(findings, fs...)
		}
	}
	return findings, nil
}

type trivyReport struct {
	Results []struct {
		Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

func scanImage(ctx context.Context, r platform.CommandRunner, image, service string) ([]model.Finding, error) {
	out, err := r.Run(ctx, "trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--format", "json", "--quiet", "--no-progress", image)
	if err != nil {
		return nil, err
	}
	return parseTrivy(out, image, service)
}

func parseTrivy(out []byte, image, service string) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decode trivy output for %s: %w", image, err)
	}

	var findings []model.Finding
	seen := map[string]bool{}
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			findings = append(findings, vulnFinding(v, image, service))
		}
	}
	return findings, nil
}

func vulnFinding(v trivyVuln, image, service string) model.Finding {
	// A vulnerability with no upstream fix is Unavailable — set here, at
	// the source that has the data, instead of via a post-scan override.
	rem := model.RemediationReview
	howToFix := fmt.Sprintf("Update the image so %s is at least %s (e.g. pin a newer tag and `docker compose pull && up -d`).", v.PkgName, v.FixedVersion)
	if v.FixedVersion == "" {
		rem = model.RemediationUnavailable
		howToFix = "No patched version is available upstream yet. Track the advisory; consider mitigations or an alternative image if the risk is high."
	}

	title := v.Title
	if title == "" {
		title = fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName)
	}

	opts := []model.FindingOption{
		model.WithService(service),
		model.WithDescription(fmt.Sprintf("The image %s ships %s %s, which is affected by %s.", image, v.PkgName, v.InstalledVersion, v.VulnerabilityID)),
		model.WithHowToFix(howToFix),
		model.WithEvidence("package", v.PkgName+"@"+v.InstalledVersion),
		model.WithEvidence("image", image),
	}
	if v.FixedVersion != "" {
		opts = append(opts, model.WithEvidence("fixed_version", v.FixedVersion))
	}
	if v.PrimaryURL != "" {
		opts = append(opts, model.WithEvidence("url", v.PrimaryURL))
	}

	return model.NewFinding("cve."+strings.ToLower(v.VulnerabilityID), title,
		trivySeverity(v.Severity), model.SourceCVE, rem, opts...)
}

func trivySeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityMedium
	}
}
