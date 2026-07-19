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
	"strconv"
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
			fs, err := scanImage(ctx, env.Runner, svc.Image, svc.Name, p.File, p.Name)
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

	// Case order matters: with no images at all, failed and attempted are both
	// zero and the clean case must win.
	switch failed {
	case 0:
		// Includes the no-images case: a host with no containers genuinely
		// has no image vulnerabilities.
		return findings, nil
	case attempted:
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

func scanImage(ctx context.Context, r platform.CommandRunner, image, service, file, project string) ([]model.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, imageTimeout+time.Minute)
	defer cancel()

	out, err := r.Run(ctx, "trivy", "image",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--timeout", imageTimeout.String(),
		"--format", "json", "--quiet", "--no-progress", image)
	if err != nil {
		return nil, err
	}
	return parseTrivy(out, image, service, file, project)
}

func parseTrivy(out []byte, image, service, file, project string) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decode trivy output for %s: %w", image, err)
	}

	var findings []model.Finding
	seen := map[string]bool{}
	// Accumulated for the per-image rollup: the fixable subset is what a
	// re-pull could plausibly address, so the rollup's severity is drawn
	// from it alone. An unfixable Critical must not inflate a finding whose
	// remediation cannot touch it.
	fixable := 0
	worstSev := model.SeverityLow
	worstCVE := ""
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			findings = append(findings, vulnFinding(v, image, service, file, project))
			if v.FixedVersion == "" {
				continue
			}
			if sev := trivySeverity(v.Severity); fixable == 0 || sev.Penalty() > worstSev.Penalty() {
				worstSev, worstCVE = sev, v.VulnerabilityID
			}
			fixable++
		}
	}
	if fixable > 0 {
		findings = append(findings, rollupFinding(image, service, file, project, fixable, worstSev, worstCVE))
	}
	return findings, nil
}

func vulnFinding(v trivyVuln, image, service, file, project string) model.Finding {
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
		// Locating metadata uses the same keys as the compose checker, the
		// other consumer of compose.Discover. It does not make these
		// findings fixable — no builder matches a per-CVE ID — but it lets
		// a UI point at the file the image is declared in.
		model.WithMetadata("file", file),
		model.WithMetadata("service", service),
		model.WithMetadata("project", project),
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

// imageReferenceIsMutable reports whether re-pulling the reference could
// possibly fetch different bytes.
//
// The line is drawn at digest-vs-not, and only there. A digest is the one
// reference Docker's data model guarantees is immutable, so a pull on it is
// provably a no-op. Every other reference — :latest, :15, :15.2, no tag at
// all — is a mutable pointer by construction, and official images really do
// get rebuilt under a patch tag with refreshed base layers. Splitting
// "floating" from "exact" tags by their spelling would need a heuristic that
// is wrong for :2024-01-15, :v1.2.3-alpine and :stable — and wrong in the
// unsafe direction, suppressing a real fix on the strength of a string.
func imageReferenceIsMutable(image string) bool {
	return !strings.Contains(image, "@")
}

// rollupFinding is the per-image summary that carries the only CVE
// remediation hostveil can actually perform. See the fix registry's doc
// comment for why the per-CVE findings stay unfixable while this one does
// not.
//
// Key() is source|id|service, so two images whose first-listed service names
// collide across projects would dedup into one. That is theoretical, the CVE
// axis is saturated well before it matters, and encoding the project into
// Service would break the RestartHint semantics ApplyFix relies on.
func rollupFinding(image, service, file, project string, fixable int, sev model.Severity, worstCVE string) model.Finding {
	mutable := imageReferenceIsMutable(image)

	rem := model.RemediationReview
	reference := "tag"
	howToFix := fmt.Sprintf("Re-pull the image and recreate the service: `docker compose -f %s pull %s && docker compose -f %s up -d %s`. This re-resolves the tag to whatever it points at now; it does not guarantee that every listed CVE is fixed.", file, service, file, service)
	if !mutable {
		rem = model.RemediationManual
		reference = "digest"
		howToFix = "This service pins its image by digest, so pulling cannot change it. Find a newer digest whose base layer ships the patched packages and update the pin. hostveil cannot compute which digest carries the fixes, so it will not guess."
	}

	return model.NewFinding("cve.outdated-image",
		"Image has vulnerabilities with published fixes",
		sev, model.SourceCVE, rem,
		model.WithService(service),
		model.WithDescription(fmt.Sprintf("The image %s has %d vulnerabilit%s with a fix published upstream, the most severe being %s. These are counted individually elsewhere in this report; this finding is the one place they can be acted on together.",
			image, fixable, plural(fixable), worstCVE)),
		model.WithHowToFix(howToFix),
		model.WithEvidence("image", image),
		model.WithEvidence("fixable_count", strconv.Itoa(fixable)),
		model.WithEvidence("worst_cve", worstCVE),
		model.WithEvidence("reference", reference),
		model.WithMetadata("file", file),
		model.WithMetadata("service", service),
		model.WithMetadata("project", project),
	)
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
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
