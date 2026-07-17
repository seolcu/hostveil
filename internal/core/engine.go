// Package core is hostveil's shared engine: the single object every UI
// (CLI, TUI, Web) calls. All scanning, scoring, and — in later phases —
// fix preview/apply/rollback orchestration lives here exactly once, so no
// UI ever re-implements it.
package core

import (
	"context"
	"encoding/json"
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

	mu        sync.RWMutex
	current   model.Report
	hasRun    bool
	lastDelta model.Delta
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

// Scan runs every checker concurrently, scores the merged findings, stores
// the result as the engine's current report, and returns it. progress may
// be nil; if non-nil it receives a ScanEvent as each checker starts and
// finishes.
func (e *Engine) Scan(ctx context.Context, progress chan<- model.ScanEvent) model.Report {
	env := platform.Detect(ctx, e.runner)
	results := e.registry.Run(ctx, env, progress)

	var findings []model.Finding
	ran := make(map[model.Source]bool, len(results))
	domains := make([]model.DomainResult, 0, len(results))

	for _, r := range results {
		ran[r.Source] = r.State.Ran()
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
		Score:    model.ScoreReport(findings, ran),
		Domains:  domains,
	}

	// Compute the delta against the previous saved scan (for the re-check
	// loop), then persist this one.
	delta := e.deltaAgainstLast(report)
	e.persist(report)

	e.mu.Lock()
	e.current = report
	e.hasRun = true
	e.lastDelta = delta
	e.mu.Unlock()

	return report
}

// LastDelta returns how the most recent scan differed from the one before
// it (resolved / new / still-present findings).
func (e *Engine) LastDelta() model.Delta {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastDelta
}

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
func (e *Engine) Current() (model.Report, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current, e.hasRun
}

// classify makes the fix registry authoritative for remediation: a
// finding is Auto/Review exactly when a matching fix is registered (its
// Kind wins). A finding whose checker intended a fix but has none
// registered is demoted to Manual, so the UI never shows a fix button
// that leads nowhere. Unavailable/Manual intents are left as-is.
func (e *Engine) classify(findings []model.Finding) {
	for i := range findings {
		if e.fixes != nil {
			if fx, ok, err := e.fixes.Build(findings[i]); ok && err == nil && fx.Kind.IsFixable() {
				findings[i].Remediation = fx.Kind
				continue
			}
		}
		if findings[i].Remediation.IsFixable() {
			findings[i].Remediation = model.RemediationManual
		}
	}
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
