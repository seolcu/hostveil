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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	var targets []target
	scanned := map[string]bool{}
	add := func(t target) {
		if t.image == "" || scanned[t.image] {
			return
		}
		scanned[t.image] = true
		targets = append(targets, t)
	}

	for _, p := range projects {
		for _, name := range sortedServiceNames(p) {
			svc := p.Services[name]
			add(target{image: svc.Image, service: svc.Name, file: p.File, project: p.Name})
		}
	}

	// Images belonging to containers no compose file describes. Without
	// these, a hand-started container's vulnerabilities were not merely
	// unreported — the axis scored as though the image were not on the host.
	// A failure to enumerate these is tracked apart from a failure to scan an
	// image. Folding it into the image counters would make "3 of 4 images
	// scanned" mean two different things, and could make a host whose only
	// images all scanned cleanly look like a total failure.
	standalone, enumErr := compose.DiscoverContainers(ctx, env.Runner)
	for _, c := range standalone {
		add(target{image: c.Service.Image, service: c.Name, standalone: true})
	}

	findings, failed, firstErr := scanAll(ctx, env.Runner, targets)
	attempted := len(targets)

	// Case order matters: with no images at all, failed and attempted are both
	// zero and the clean case must win.
	switch failed {
	case 0:
		if enumErr != nil {
			// Every image we knew about scanned, but we could not find out
			// which containers exist outside Compose — so the axis covered
			// less ground than a clean result would claim.
			return findings, &check.PartialError{
				Reason: "scanned compose images only — cannot enumerate containers started outside Compose",
			}
		}
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

// target is one image to scan, plus the attribution its findings carry.
// standalone marks a container no compose file describes, whose findings are
// demoted to Manual because the registered fix has no file to act on.
type target struct {
	image      string
	service    string
	file       string
	project    string
	standalone bool
}

// scanParallelism bounds how many Trivy processes run at once.
//
// The scan was serial, and Trivy is the slowest thing hostveil runs: a host
// with twenty images spent twenty sequential image scans in a domain the
// other eight checkers had long since finished. The cap exists because the
// opposite mistake is just as easy — Trivy is CPU- and IO-heavy, and one
// process per image on a small VPS would thrash the box hostveil is meant to
// be looking after gently. Four keeps the pipeline full without becoming the
// load spike.
const scanParallelism = 4

// scanAll scans every target with bounded concurrency and returns the merged
// findings, how many failed, and the first failure in target order.
//
// Results are collected by index rather than appended as they arrive, so the
// findings and the reported error do not depend on which Trivy process
// happened to finish first. A scan that reordered its own output between runs
// would show up as a spurious delta on the next re-scan.
func scanAll(ctx context.Context, r platform.CommandRunner, targets []target) (findings []model.Finding, failed int, firstErr error) {
	type result struct {
		findings []model.Finding
		err      error
	}
	results := make([]result, len(targets))

	var wg sync.WaitGroup
	slots := make(chan struct{}, scanParallelism)
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			fs, err := scanImage(ctx, r, t.image, t.service, t.file, t.project)
			if err == nil && t.standalone {
				fs = demoteToManual(fs)
			}
			results[i] = result{findings: fs, err: err}
		}()
	}
	wg.Wait()

	for _, res := range results {
		if res.err != nil {
			failed++
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		findings = append(findings, res.findings...)
	}
	return findings, failed, firstErr
}

// sortedServiceNames returns a project's service names in a stable order.
// Ranging a map directly would vary the scan order between runs, which
// decides which image's failure is reported as the first one.
func sortedServiceNames(p compose.Project) []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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

// demoteToManual marks findings for an image whose container has no compose
// file. The registered fix for cve.outdated-image runs
// `docker compose -f <file> pull <service>`, and there is no file — so the
// checker declares Manual and Engine.classify, which takes whichever side
// demands more human involvement, keeps the registry from offering a fix
// that could not run.
func demoteToManual(fs []model.Finding) []model.Finding {
	for i := range fs {
		fs[i].Remediation = model.RemediationManual
		fs[i].HowToFix = "This container was started with `docker run`, not Compose, so hostveil cannot update it for you. " +
			"Pull the image and recreate the container yourself. " + fs[i].HowToFix
		if fs[i].Evidence == nil {
			fs[i].Evidence = map[string]string{}
		}
		fs[i].Evidence["managed_by"] = "docker run"
	}
	return fs
}

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

	// Split into the two groups that have genuinely different remediations:
	// vulnerabilities a newer image could fix, and vulnerabilities nobody has
	// fixed yet. Everything within a group shares one remediation, which is
	// why the group — not the individual CVE — is the finding.
	var fixable, unpatched group
	seen := map[string]bool{}
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if v.VulnerabilityID == "" || seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			if v.FixedVersion != "" {
				fixable.add(v)
			} else {
				unpatched.add(v)
			}
		}
	}

	var findings []model.Finding
	if f, ok := outdatedFinding(image, service, file, project, fixable); ok {
		findings = append(findings, f)
	}
	if f, ok := unpatchedFinding(image, service, file, project, unpatched); ok {
		findings = append(findings, f)
	}
	return findings, nil
}

// group accumulates one remediation-class of vulnerabilities for an image.
type group struct {
	ids    []string
	counts map[model.Severity]int
	sevOf  map[string]model.Severity
}

func (g *group) add(v trivyVuln) {
	if g.counts == nil {
		g.counts = map[model.Severity]int{}
		g.sevOf = map[string]model.Severity{}
	}
	sev := trivySeverity(v.Severity)
	g.ids = append(g.ids, v.VulnerabilityID)
	g.counts[sev]++
	g.sevOf[v.VulnerabilityID] = sev
}

func (g *group) empty() bool { return len(g.ids) == 0 }

// sorted returns the group's CVE IDs worst-first, ties broken by ID.
// Deterministic ordering matters: these feed a description that would
// otherwise reshuffle on every scan and read as a change.
func (g *group) sorted() []string {
	out := slices.Clone(g.ids)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := g.sevOf[out[i]], g.sevOf[out[j]]
		if a != b {
			return a < b // Severity is ordered most-severe-first
		}
		return out[i] < out[j]
	})
	return out
}

// worst returns the severity the finding carries: the most severe member of
// this group alone. A group's severity must never be borrowed from the other
// one — an unfixable Critical must not inflate a finding whose remediation
// cannot touch it, and vice versa.
func (g *group) worst() model.Severity { return g.sevOf[g.sorted()[0]] }

// summary renders "12 critical, 108 high" for the severities present.
func (g *group) summary() string {
	var parts []string
	for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if n := g.counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.String())))
		}
	}
	return strings.Join(parts, ", ")
}

// worstList names up to maxNamed of the most severe CVEs. Naming a bounded
// handful keeps the description readable in the TUI, whose detail view does
// not scroll; the full list lives in evidence for --json.
const maxNamed = 5

func (g *group) worstList() string {
	ids := g.sorted()
	if len(ids) <= maxNamed {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:maxNamed], ", ") + fmt.Sprintf(", and %d more", len(ids)-maxNamed)
}

// evidence attaches the machine-readable detail. The CVE list is joined with
// ", " rather than "," on purpose: clirender's wrap splits on whitespace, so
// a comma-only list would be one unbreakable word that overflows a terminal
// the day anything starts rendering evidence.
func (g *group) evidence() []model.FindingOption {
	opts := []model.FindingOption{
		model.WithEvidence("count", strconv.Itoa(len(g.ids))),
		model.WithEvidence("cves", strings.Join(g.sorted(), ", ")),
	}
	for _, s := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow} {
		if n := g.counts[s]; n > 0 {
			opts = append(opts, model.WithEvidence(strings.ToLower(s.String()), strconv.Itoa(n)))
		}
	}
	return opts
}

// imageService qualifies the compose service with its project.
//
// Finding.Key() is source|id|service, and these findings share one ID per
// image, so the service is the only thing distinguishing them. Two projects
// that each name a service "db" while running different images would collide
// and silently dedup one image out of the report entirely. (project, service)
// is unique host-wide: compose enforces unique service names within a
// project, and `docker compose ls` unique project names across them.
//
// The fix builder reads the bare service name from Metadata["service"], since
// that is what `docker compose -f <file> pull <svc>` needs.
func imageService(project, service string) string {
	if project == "" {
		return service
	}
	return project + "/" + service
}

func imageOpts(image, service, file, project string) []model.FindingOption {
	return []model.FindingOption{
		model.WithService(imageService(project, service)),
		model.WithEvidence("image", image),
		model.WithMetadata("file", file),
		model.WithMetadata("service", service),
		model.WithMetadata("project", project),
	}
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

// outdatedFinding reports the vulnerabilities a newer image would fix. It
// carries the only CVE remediation hostveil can actually perform; see the fix
// registry's doc comment for why no per-CVE finding does.
func outdatedFinding(image, service, file, project string, g group) (model.Finding, bool) {
	if g.empty() {
		return model.Finding{}, false
	}

	rem := model.RemediationReview
	reference := "tag"
	howToFix := fmt.Sprintf("Re-pull the image and recreate the service: `docker compose -f %s pull %s && docker compose -f %s up -d %s`. This re-resolves the tag to whatever it points at now; it does not guarantee that every listed CVE is fixed.", file, service, file, service)
	if !imageReferenceIsMutable(image) {
		rem = model.RemediationManual
		reference = "digest"
		howToFix = "This service pins its image by digest, so pulling cannot change it. Find a newer digest whose base layer ships the patched packages and update the pin. hostveil cannot compute which digest carries the fixes, so it will not guess."
	}

	opts := append(imageOpts(image, service, file, project),
		model.WithDescription(fmt.Sprintf("The image %s ships %d vulnerabilit%s that are already fixed upstream (%s). Most severe: %s. Run with --json for the full list.",
			image, len(g.ids), plural(len(g.ids)), g.summary(), g.worstList())),
		model.WithHowToFix(howToFix),
		model.WithEvidence("reference", reference),
		model.WithEvidence("worst_cve", g.sorted()[0]),
	)
	opts = append(opts, g.evidence()...)

	return model.NewFinding("cve.outdated-image",
		"Image has vulnerabilities with published fixes",
		g.worst(), model.SourceCVE, rem, opts...), true
}

// unpatchedFinding reports the vulnerabilities nobody has fixed yet.
//
// It exists so that an image whose vulnerabilities are ALL unfixed still
// produces a finding. Without it, aggregating per-CVE findings away would
// make such a host look clean — the same "couldn't look means nothing there"
// lie this domain told once before, arrived at from the other direction. It
// also keeps `hostveil scan`'s non-zero exit working for an image whose only
// Critical has no patch.
func unpatchedFinding(image, service, file, project string, g group) (model.Finding, bool) {
	if g.empty() {
		return model.Finding{}, false
	}

	opts := append(imageOpts(image, service, file, project),
		model.WithDescription(fmt.Sprintf("The image %s ships %d vulnerabilit%s with no patched version available upstream (%s). Most severe: %s. Run with --json for the full list.",
			image, len(g.ids), plural(len(g.ids)), g.summary(), g.worstList())),
		model.WithHowToFix("There is nothing to update to yet. Track the advisories, and consider whether the exposed component is reachable in your setup, whether a mitigation exists, or whether a differently-based image would carry less risk."),
	)
	opts = append(opts, g.evidence()...)

	return model.NewFinding("cve.unpatched-image",
		"Image has vulnerabilities with no fix available",
		g.worst(), model.SourceCVE, model.RemediationUnavailable, opts...), true
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
