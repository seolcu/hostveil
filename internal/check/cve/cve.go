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
	"time"

	"github.com/seolcu/hostveil/internal/check"
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

// Available requires both Trivy (the scanner) and a reachable Docker daemon
// (to enumerate the images to scan). Missing either yields a clean skip.
//
// The daemon is probed, not merely looked up on PATH: an unreachable socket
// would otherwise let the scan proceed, fail on every image, and report zero
// vulnerabilities — a perfect CVE score for a scan that never happened.
func (*Checker) Available(ctx context.Context, env platform.Env) (bool, string) {
	if !platform.Has(env.Runner, "trivy") {
		return false, "Trivy not installed — CVE scan skipped (install it to enable image vulnerability scanning)"
	}
	if ok, reason := platform.DockerReachable(ctx, env.Runner); !ok {
		return false, reason + " — no images to scan"
	}
	return true, ""
}

// Check enumerates compose images and scans each with Trivy.
//
// Per-image failures are counted rather than swallowed, because "no
// vulnerabilities found" and "nothing could be examined" score identically
// but mean opposite things. Some images unscannable is Degraded; all of them
// is an outright error, which drops the axis from scoring entirely.
func (*Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	projects, err := compose.Discover(ctx, env.Runner)
	if err != nil {
		return nil, err
	}

	var findings []model.Finding
	var attempted, failed int
	var firstErr error
	scanned := map[string]bool{}
	for _, p := range projects {
		for _, svc := range p.Services {
			if svc.Image == "" || scanned[svc.Image] {
				continue
			}
			scanned[svc.Image] = true
			attempted++
			fs, err := scanImage(ctx, env.Runner, svc.Image, svc.Name)
			if err != nil {
				failed++
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			findings = append(findings, fs...)
		}
	}

	switch {
	case failed == 0:
		// Includes the no-images case: a host with no containers genuinely
		// has no image vulnerabilities.
		return findings, nil
	case failed == attempted:
		return nil, fmt.Errorf("no image could be scanned: %w", firstErr)
	default:
		return findings, &check.PartialError{
			Reason:  fmt.Sprintf("some images could not be scanned (first failure: %v)", firstErr),
			Covered: attempted - failed,
			Total:   attempted,
		}
	}
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

// imageTimeout bounds a single image scan. Trivy downloads its vulnerability
// DB on first use and falls back to pulling from a remote registry when it
// cannot read an image locally, so an unbounded scan can hang for as long as
// the network allows — the flag makes Trivy exit with a legible message, and
// the context guarantees termination if it hangs before parsing its own flags.
const imageTimeout = 5 * time.Minute

func scanImage(ctx context.Context, r platform.CommandRunner, image, service string) ([]model.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, imageTimeout+time.Minute)
	defer cancel()

	out, err := r.Run(ctx, "trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--timeout", imageTimeout.String(),
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
