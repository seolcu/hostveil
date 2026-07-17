// Package core is hostveil's shared engine: the single object every UI
// (CLI, TUI, Web) calls. All scanning, scoring, and — in later phases —
// fix preview/apply/rollback orchestration lives here exactly once, so no
// UI ever re-implements it.
package core

import (
	"context"
	"sync"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Config wires an Engine's dependencies.
type Config struct {
	Registry *check.Registry
	Runner   platform.CommandRunner // nil = platform.DefaultRunner
}

// Engine holds the checker registry and the most recent scan result.
type Engine struct {
	registry *check.Registry
	runner   platform.CommandRunner

	mu      sync.RWMutex
	current model.Report
	hasRun  bool
}

// New builds an Engine from cfg.
func New(cfg Config) *Engine {
	runner := cfg.Runner
	if runner == nil {
		runner = platform.DefaultRunner{}
	}
	return &Engine{registry: cfg.Registry, runner: runner}
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

	model.SortFindings(findings)
	report := model.Report{
		Findings: findings,
		Score:    model.ScoreReport(findings, ran),
		Domains:  domains,
	}

	e.mu.Lock()
	e.current = report
	e.hasRun = true
	e.mu.Unlock()

	return report
}

// Current returns the last stored report and whether a scan has run.
func (e *Engine) Current() (model.Report, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.current, e.hasRun
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
