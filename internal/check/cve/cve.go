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
	projects, unparsed, err := compose.Discover(ctx, env.Runner)
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
		for _, name := range p.ServiceNames() {
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

	// Every image failing is not partial coverage, it is none, and it leaves
	// before the ledger because it is the one outcome that is not a matter of
	// degree: a Degraded domain is still scored, so reporting it here would
	// hand back a scored axis built on nothing. The attempted > 0 guard is
	// what keeps a host with no containers at all — where failed and
	// attempted are both zero — on the clean path.
	if attempted > 0 && failed == attempted {
		return nil, fmt.Errorf("no image could be scanned: %w", firstErr)
	}

	// Each blind spot is recorded rather than returned, so hitting two of
	// them reports two. Returning at the first is how an unparsed compose
	// file used to disappear from a scan that also had an image fail.
	var cov check.Coverage
	cov.Covered(attempted - failed)
	if failed > 0 {
		cov.Missed(failed, fmt.Sprintf("some images could not be scanned (first failure: %v)", firstErr))
	}
	// A compose file we could not parse is a set of images we never even knew
	// to scan, so it degrades the axis exactly like a failed enumeration does
	// — the images are absent from `attempted`, and without this the axis
	// would score as if they did not exist.
	if len(unparsed) > 0 {
		cov.Missed(len(unparsed), "cannot parse compose file(s): "+strings.Join(unparsed, ", ")+
			" — images defined there were not scanned")
	}
	// Every image we knew about scanned, but we could not find out which
	// containers exist outside Compose — so the axis covered less ground than
	// a clean result would claim. It carries no unit count: the images it
	// would have added are exactly the ones that could not be enumerated.
	if enumErr != nil {
		cov.Missed(0, "scanned compose images only — cannot enumerate containers started outside Compose")
	}
	// Nothing missed includes the no-images case: a host with no containers
	// genuinely has no image vulnerabilities.
	return findings, cov.Err()
}

// target is one image to scan, plus the attribution its findings carry.
// standalone marks a container no compose file describes, whose findings are
// demoted to Manual because the registered fix has no file to act on.
// target is one image to scan and where it came from.
//
// The four strings travel together because they were travelling together
// anyway — as four positional parameters on scanImage, parseTrivy, imageOpts,
// outdatedFinding and unpatchedFinding, in that order, five times. Four
// adjacent same-typed arguments transpose silently: swap service and file and
// the finding names a path as its service and a service as its file, renders
// without complaint, and is wrong in the two fields an operator uses to find
// the thing.
//
// internal/ui/tui's Opts already states this rule for itself — "one struct
// rather than three parameters because the third would have been the one that
// tipped the signature into being read wrong at a call site." This is the same
// rule, one argument later.
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

// dbTimeout bounds the one-off vulnerability-DB download in warmCache. It is
// the same budget a single image scan gets, because on a cold cache that is
// most of what an image scan spends its time on.
const dbTimeout = 5 * time.Minute

// memoryCache makes a Trivy process keep its analysis cache to itself instead
// of in the shared directory, which is what allows more than one of them to
// run at a time.
//
// Trivy's filesystem cache is a single-writer BoltDB. Two processes that both
// want it is not a rare interleaving — it is the ordinary case when four start
// together, and the loser does not degrade, it exits: "unable to initialize fs
// cache: cache may be in use by another process". So the parallelism above was
// quietly costing coverage on every scan it sped up.
//
// The damage is not that findings go missing. It is that they go missing in
// the flattering direction: an image that could not be scanned contributes no
// vulnerabilities, so the axis reads *better* the less of the host it saw. The
// demo VM's vulnerability axis scored 44/100 on a run that reached 1 of its 7
// images, 25/100 on a run that reached 3, and 16/100 — the truth — on the run
// that reached all seven.
//
// hostveil said "partial" every time, which is the coverage machinery working
// exactly as designed: a domain that could not look never claims it found
// nothing. But a Degraded axis is still scored, deliberately, so the honest
// flag sat beside a number that was wrong by 28 points.
//
// Warming the cache first is the obvious fix and it is not enough. Four
// concurrent scans on that host, controlled for image set and run against an
// already-populated cache:
//
//	shared cache   3 of 4 succeed   one exits on the lock
//	this commit    4 of 4
//
// because the contention is over the lock rather than over the contents.
var memoryCache = []string{"--cache-backend", "memory"}

// warmCache downloads the vulnerability DB before the fan-out, and reports
// whether Trivy accepted the memory cache backend.
//
// Both halves are needed and neither is sufficient. Without the DB on disk,
// four scans race to download it and *all four* fail, memory backend or not —
// the backend only decides where an image's analysis goes, and the DB is
// shared either way. Without the memory backend, they race for the cache lock.
//
// It doubles as the capability probe, which is why it carries the flag it is
// testing: `--cache-backend` is marked experimental, `memory` is newer than
// the flag itself, and an unsupported value fails immediately and legibly
// ("unknown cache type"). Nothing here can tell that apart from a download
// that failed for want of a network, and it does not need to — either way the
// fast path is not available, and the caller falls back to scanning one image
// at a time, which is correct on every version of Trivy there has ever been.
// Downloading the DB with the flag set is safe: the backend governs the
// analysis cache only, and the DB still lands on disk where the scans will
// find it.
//
// Costs 45ms once the DB is present.
func warmCache(ctx context.Context, r platform.CommandRunner) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout+time.Minute)
	defer cancel()

	args := append([]string{"image", "--download-db-only",
		"--timeout", dbTimeout.String(), "--quiet", "--no-progress"}, memoryCache...)
	_, err := r.Run(ctx, "trivy", args...)
	return err
}

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

	// One target races nothing, so it takes the plain path: the shared cache
	// it populates is the one a later scan of the same image will reuse.
	//
	// For more than one, the fast path has to be earned. Where Trivy will not
	// give both halves of it, the scans go one at a time rather than four at
	// a time into a lock they cannot share — slower than this domain was
	// yesterday, and the first version of it that reports what it actually
	// examined.
	cacheArgs, parallelism := []string(nil), 1
	if len(targets) > 1 && warmCache(ctx, r) == nil {
		cacheArgs, parallelism = memoryCache, scanParallelism
	}

	var wg sync.WaitGroup
	slots := make(chan struct{}, parallelism)
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			fs, err := scanImage(ctx, r, cacheArgs, t)
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
		// See the same line in internal/check/compose: these IDs are
		// registered, so fix.WhyNoFix has nothing to say about them, and the
		// panel that exists to answer "why is there no button" was blank.
		fs[i].WhyNoFix = "This container was started with `docker run`, not Compose, so there is no compose file to pull through."
		fs[i].HowToFix = "This container was started with `docker run`, not Compose, so Hostveil cannot update it for you. " +
			"Pull the image and recreate the container yourself. " + fs[i].HowToFix
		if fs[i].Evidence == nil {
			fs[i].Evidence = map[string]string{}
		}
		fs[i].Evidence["managed_by"] = "docker run"
	}
	return fs
}

// scanImage scans one image. cacheArgs is the cache-backend selection scanAll
// settled on for this run, empty where the scans are running one at a time and
// the shared cache is safe to use.
func scanImage(ctx context.Context, r platform.CommandRunner, cacheArgs []string, t target) ([]model.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, imageTimeout+time.Minute)
	defer cancel()

	args := append([]string{"image",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--timeout", imageTimeout.String(),
		"--format", "json", "--quiet", "--no-progress"}, cacheArgs...)
	out, err := r.Run(ctx, "trivy", append(args, t.image)...)
	if err != nil {
		return nil, err
	}
	return parseTrivy(out, t)
}

func parseTrivy(out []byte, t target) ([]model.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("decode trivy output for %s: %w", t.image, err)
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
	if f, ok := outdatedFinding(t, fixable); ok {
		findings = append(findings, f)
	}
	if f, ok := unpatchedFinding(t, unpatched); ok {
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

// summary renders "12 high, 108 medium" for the severities present.
//
// It walks model.AllSeverities rather than a list written out here. The list
// written out here was the four-level scale, and when Critical and High
// merged into one constant both rows stayed — so the same constant was read
// twice and a group of two top-severity vulnerabilities rendered as
// "2 high, 2 high". The scale is the model's to enumerate, and a copy of it
// in this file is a copy that goes stale exactly when the model changes.
func (g *group) summary() string {
	var parts []string
	for _, s := range model.AllSeverities() {
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
	// AllSeverities for the reason summary gives: the list this used to
	// write out held the merged constant twice, so the same evidence key was
	// added twice with the same value.
	for _, s := range model.AllSeverities() {
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

func imageOpts(t target) []model.FindingOption {
	return []model.FindingOption{
		model.WithService(imageService(t.project, t.service)),
		model.WithEvidence("image", t.image),
		model.WithMetadata("file", t.file),
		model.WithMetadata("service", t.service),
		model.WithMetadata("project", t.project),
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
func outdatedFinding(t target, g group) (model.Finding, bool) {
	if g.empty() {
		return model.Finding{}, false
	}

	rem := model.RemediationReview
	reference := "tag"
	howToFix := fmt.Sprintf("Re-pull the image and recreate the service: `docker compose -f %s pull %s && docker compose -f %s up -d %s`. This re-resolves the tag to whatever it points at now; it does not guarantee that every listed CVE is fixed.", t.file, t.service, t.file, t.service)
	if !imageReferenceIsMutable(t.image) {
		rem = model.RemediationManual
		reference = "digest"
		howToFix = "This service pins its image by digest, so pulling cannot change it. Find a newer digest whose base layer ships the patched packages and update the pin. Hostveil cannot compute which digest carries the fixes, so it will not guess."
	}

	opts := append(imageOpts(t),
		model.WithDescription(fmt.Sprintf("The image %s ships %d vulnerabilit%s that are already fixed upstream (%s). Most severe: %s. Run with --json for the full list.",
			t.image, len(g.ids), plural(len(g.ids)), g.summary(), g.worstList())),
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
func unpatchedFinding(t target, g group) (model.Finding, bool) {
	if g.empty() {
		return model.Finding{}, false
	}

	opts := append(imageOpts(t),
		model.WithDescription(fmt.Sprintf("The image %s ships %d vulnerabilit%s with no patched version available upstream (%s). Most severe: %s. Run with --json for the full list.",
			t.image, len(g.ids), plural(len(g.ids)), g.summary(), g.worstList())),
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
		return model.SeverityHigh
	case "HIGH":
		return model.SeverityHigh
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityMedium
	}
}
