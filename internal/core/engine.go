// Package core is hostveil's shared engine: the single object every UI
// (CLI, TUI, Web) calls. All scanning, scoring, and fix
// preview/apply/rollback orchestration lives here exactly once, so no UI
// ever re-implements it.
package core

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/seolcu/hostveil/internal/ai"
	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Config wires an Engine's dependencies.
type Config struct {
	Registry *check.Registry
	Fixes    *fix.Registry          // nil = no fixes; all fixable findings become Manual
	Store    *history.Store         // nil = default per-user dir
	Runner   platform.CommandRunner // nil = platform.DefaultRunner
	AI       ai.Explainer           // nil = ai.Noop (advisory AI disabled)
}

// Engine holds the checker registry, fix registry, recovery store, and the
// most recent scan result.
type Engine struct {
	registry *check.Registry
	fixes    *fix.Registry
	store    *history.Store
	runner   platform.CommandRunner
	ai       ai.Explainer

	// applyMu serializes everything that mutates the host or replaces the
	// current report: scans, fix applications, and rollbacks. It is always
	// taken OUTSIDE the report state's own lock, never while holding it.
	//
	// Without it the web dashboard — which serves requests concurrently —
	// could run two applyEdits against one compose file at once. Each reads
	// the file, transforms its own copy, and writes; the later write erases
	// the earlier fix while both checkpoints record success and both findings
	// are marked Fixed. That is silent data loss in the one subsystem whose
	// entire promise is that changes are recorded and reversible.
	applyMu sync.Mutex

	// state is the last scan and everything derived from it. It carries
	// its own lock, which is always taken INSIDE applyMu, never around it.
	state reportState
}

// New builds an Engine from cfg.
func New(cfg Config) *Engine {
	runner := cfg.Runner
	if runner == nil {
		runner = platform.DefaultRunner{}
	}
	store := cfg.Store
	if store == nil {
		store = history.NewStore(history.DefaultDir())
	}
	explainer := cfg.AI
	if explainer == nil {
		explainer = ai.Noop{}
	}
	return &Engine{registry: cfg.Registry, fixes: cfg.Fixes, store: store, runner: runner, ai: explainer}
}

// ScanOptions narrows what a scan covers. The zero value is a full scan.
type ScanOptions struct {
	// Only limits the scan to these domains. Empty means every registered
	// checker runs.
	Only []model.Source
}

// Partial reports whether the options describe less than a full scan.
func (o ScanOptions) Partial() bool { return len(o.Only) > 0 }

// Scan runs every checker concurrently, scores the merged findings, stores
// the result as the engine's current report, and returns it. progress may
// be nil; if non-nil it receives a ScanEvent as each checker starts and
// finishes.
func (e *Engine) Scan(ctx context.Context, progress chan<- model.ScanEvent) model.Report {
	return e.ScanWith(ctx, progress, ScanOptions{})
}

// ScanWith is Scan with domain selection.
//
// A partial scan is never persisted and computes no delta. Saving it would
// make the partial report the baseline: the next full scan would announce
// every finding from the skipped domains as newly appeared, and the
// operator's last complete report on disk would have been overwritten by a
// narrower one. The in-memory current report is still replaced, so a fix
// in the same process works on what was just scanned.
func (e *Engine) ScanWith(ctx context.Context, progress chan<- model.ScanEvent, opts ScanOptions) model.Report {
	// A scan replaces the current report wholesale, so it must not overlap a
	// fix: the replacement would drop the Fixed flag the fix had just set,
	// and the scan would be reading files another goroutine is mid-write on.
	e.applyMu.Lock()
	defer e.applyMu.Unlock()

	// Checkers are read-only and run concurrently, and several of them ask
	// the host the same questions — `docker compose ls`, `docker inspect`
	// over every container, the firewall probe. The cache collapses those to
	// one execution each for the duration of this scan. It deliberately does
	// not replace e.runner: fixes run through the uncached one, because an
	// exec fix mutates the host and must never be served from a cache.
	env := platform.Detect(ctx, platform.NewScanCache(e.runner))
	registry := e.registry
	if opts.Partial() {
		var subset []check.Checker
		for _, c := range e.registry.Checkers() {
			if slices.Contains(opts.Only, c.Source()) {
				subset = append(subset, c)
			}
		}
		registry = check.NewRegistry(subset...)
	}
	results := registry.Run(ctx, env, progress)

	var findings []model.Finding
	states := make(map[model.Source]model.ScanState, len(results))
	domains := make([]model.DomainResult, 0, len(results))

	for _, r := range results {
		states[r.Source] = r.State
		valid := validFindings(r.Findings)
		findings = append(findings, valid...)
		domains = append(domains, model.DomainResult{
			Source:       r.Source,
			State:        r.State,
			Reason:       r.Reason,
			FindingCount: len(valid),
		})
	}

	e.classify(findings)
	model.SortFindings(findings)
	report := model.Report{
		Findings: findings,
		Score:    model.ScoreReport(findings, states),
		Domains:  domains,
	}

	// A cancelled scan describes nothing. Every exec'd checker dies the
	// instant the context is cancelled, so what is left is a report whose
	// domains are empty because they were killed, not because the host is
	// clean — and installing it would replace a good report with that, in
	// memory and on disk. Worse, it becomes the baseline: the next scan diffs
	// against it and reports every finding on the host as newly appeared.
	//
	// The dashboard hit this by the shortest possible route. handleRescan
	// passed the request's context, so closing the browser tab mid-rescan
	// cancelled the scan, and /api/result then served a scan that never ran.
	// The request context is no longer the scan's (see ListenAndServe's
	// BaseContext), but the rule belongs here: any caller may cancel, and
	// none of them wants the wreckage kept.
	if err := ctx.Err(); err != nil {
		return report
	}

	// Compute the delta against the previous saved scan (for the re-check
	// loop), then persist this one. A partial scan does neither — see
	// ScanWith.
	var delta model.Delta
	if !opts.Partial() {
		delta = e.deltaAgainstLast(report)
		e.persist(report)
	}

	e.state.replace(report, delta)

	return report
}

// LastDelta returns how the most recent scan differed from the one before
// it (resolved / new / still-present findings).
func (e *Engine) LastDelta() model.Delta { return e.state.delta() }

// deltaAgainstLast loads the previously saved scan and diffs it against the
// fresh report. A missing or unreadable prior scan yields an empty delta.
func (e *Engine) deltaAgainstLast(curr model.Report) model.Delta {
	data, ok, err := e.store.LastReport()
	if err != nil || !ok {
		return model.Delta{}
	}
	var prev model.Report
	if json.Unmarshal(data, &prev) != nil {
		return model.Delta{}
	}
	return model.ComputeDelta(prev, curr)
}

func (e *Engine) persist(r model.Report) {
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	_ = e.store.SaveReport(history.NewScanID(), data)
}

// Current returns the last stored report and whether a scan has run.
//
// The findings are copied, not shared. Report is a struct but Findings is a
// slice, so returning it by value hands the caller the same backing array
// the engine keeps mutating — markFixed writes Fixed on those elements
// under the lock while the caller reads them outside it. The web dashboard
// hit exactly that: `go test -race` reports a write in markFixed against a
// concurrent read in json.Encoder from /api/result. Copying makes the
// returned report a snapshot, which is what every caller already assumed.
func (e *Engine) Current() (model.Report, bool) { return e.state.snapshot() }

// classify settles a finding's remediation between two sources of truth.
//
// The fix registry decides whether a fix exists at all: a finding whose
// checker intended a fix but has none registered is demoted to Manual, so
// a UI never shows a fix button that leads nowhere. That direction is
// absolute.
//
// The checker decides how much human judgment applying it needs, and the
// registry cannot talk it down. A registered fix is shaped Auto when it
// has a single mechanical action, which is a statement about the fix's
// *form*, not about whether it is safe to run unattended in a batch. Where
// the checker asked for Review, Review wins — see the standard in
// internal/fix/register.go for what each kind means.
//
// It also attaches the reason a finding has no fix, because this is the one
// place that knows a finding ended up without one. A checker cannot say it:
// it does not know what the registry holds. The registry cannot say it
// either: a finding it has a fix for can still arrive here unfixable,
// because the checker asked for Manual and the stricter side wins.
func (e *Engine) classify(findings []model.Finding) {
	for i := range findings {
		if e.fixes != nil {
			// Through buildFix, so a fix whose shape contradicts its kind is
			// treated exactly like one that failed to build: demoted here
			// rather than offered and discovered at apply.
			if fx, ok, err := e.buildFix(findings[i]); ok && err == nil && fx.Kind.IsFixable() {
				findings[i].Remediation = resolvedKind(findings[i].Remediation, fx)
			} else if findings[i].Remediation.IsFixable() {
				findings[i].Remediation = model.RemediationManual
			}
		} else if findings[i].Remediation.IsFixable() {
			findings[i].Remediation = model.RemediationManual
		}
		if !findings[i].Remediation.IsFixable() {
			findings[i].WhyNoFix = fix.WhyNoFix(findings[i].ID)
		}
	}
}

// resolvedKind is the remediation a user is shown: the checker's declared
// kind against the registered fix's effective one, taking whichever demands
// more human involvement.
//
// RemediationKind is ordered by caution (Unset < Auto < Review < Manual <
// Unavailable), so "stricter wins" is simply the larger of the two, and the
// zero value falls out correctly for free — a checker that declared no
// opinion is the least cautious thing on the scale and defers to the
// registry.
//
// The unfixable end is why this is a plain max rather than the special case
// it used to be. That case returned the registry's kind whenever the checker
// declared Manual or Unavailable, which is the exact inverse of the rule
// stated everywhere else in the repo: the checker saying "there is nothing
// safe to automate here" was overruled by a fix builder that happens to match
// the ID. Two places relied on the stated rule in their comments and were
// saved instead by their builder returning an error — internal/check/compose
// forces every runtime-only container finding to Manual because there is no
// compose file to edit, and internal/fix/compose refuses digest-pinned image
// references. Accidentally right in both, and a builder that grew a fallback
// would have turned either into a fix button leading nowhere.
func resolvedKind(declared model.RemediationKind, fx fix.Fix) model.RemediationKind {
	registered := fx.EffectiveKind()
	if declared > registered {
		return declared
	}
	return registered
}

// validFindings drops any malformed finding so an unclassified or
// unsourced finding can never reach a UI. Well-behaved checkers (which
// build via model.NewFinding) never produce these; this is the last line
// of defense enforcing the model's invariants.
func validFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	for _, f := range in {
		if f.Validate() == nil {
			out = append(out, f)
		}
	}
	return out
}

// ScoreHistory returns the headline score of every retained scan, oldest
// first, so a UI can show whether the host is getting better.
//
// The data has been on disk since the store was written — thirty snapshots,
// kept and pruned — and nothing ever read more than the newest one. Every
// interface showed "since last scan" and nothing longer, which answers
// "did that round of fixes help?" but not "is this host improving?".
//
// A snapshot that will not unmarshal is skipped rather than failing the
// call, and an unscorable scan keeps Applicable false rather than being
// flattened to zero: a run where every domain was skipped has no score, and
// drawing it as 0 would invent a cliff.
func (e *Engine) ScoreHistory() ([]model.ScorePoint, error) {
	snaps, err := e.store.ListReports()
	if err != nil {
		return nil, err
	}
	out := make([]model.ScorePoint, 0, len(snaps))
	for _, snap := range snaps {
		var r model.Report
		if json.Unmarshal(snap.Data, &r) != nil {
			continue
		}
		out = append(out, model.ScorePoint{
			At:         snap.At,
			Overall:    r.Score.Overall,
			Applicable: r.Score.Applicable,
		})
	}
	return out, nil
}
