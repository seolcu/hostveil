// Package check defines the Checker abstraction and the concurrent
// orchestrator that runs every detection domain. Adding a domain means
// writing one package that implements Checker and registering it; nothing
// else changes.
package check

import (
	"context"
	"fmt"
	"sync"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker performs read-only detection for one domain. Implementations
// must never mutate host state.
type Checker interface {
	// Source is the domain this checker owns; also the finding-ID prefix.
	Source() model.Source
	// Available reports whether the checker can run here. When a
	// dependency is absent (e.g. Docker or Trivy not installed) it returns
	// (false, reason) and the orchestrator records the domain as Skipped —
	// never an error.
	Available(ctx context.Context, env platform.Env) (ok bool, reason string)
	// Check runs detection and returns findings. "Nothing found" is
	// (nil, nil); an error signals a genuine failure.
	Check(ctx context.Context, env platform.Env) ([]model.Finding, error)
}

// Registry holds the set of checkers to run.
type Registry struct {
	checkers []Checker
}

// NewRegistry builds a registry from the given checkers, in scan order.
func NewRegistry(checkers ...Checker) *Registry {
	return &Registry{checkers: checkers}
}

// Register appends a checker.
func (r *Registry) Register(c Checker) { r.checkers = append(r.checkers, c) }

// Checkers returns the registered checkers.
func (r *Registry) Checkers() []Checker { return r.checkers }

// Result bundles one checker's outcome for the orchestrator.
type Result struct {
	Source   model.Source
	State    model.ScanState
	Reason   string
	Findings []model.Finding
}

// Run executes every checker concurrently. One checker erroring or
// panicking never aborts the others: it is recovered and recorded as an
// Error result while the rest continue. Progress is streamed to events
// (which may be nil) as each checker starts and finishes.
func (r *Registry) Run(ctx context.Context, env platform.Env, events chan<- model.ScanEvent) []Result {
	results := make([]Result, len(r.checkers))
	var wg sync.WaitGroup
	for i, c := range r.checkers {
		wg.Add(1)
		go func(i int, c Checker) {
			defer wg.Done()
			results[i] = runOne(ctx, c, env, events)
		}(i, c)
	}
	wg.Wait()
	return results
}

func runOne(ctx context.Context, c Checker, env platform.Env, events chan<- model.ScanEvent) (res Result) {
	src := c.Source()
	res = Result{Source: src, State: model.ScanRunning}
	emit(events, model.ScanEvent{Source: src, State: model.ScanRunning})

	// A panic in one checker degrades only that domain.
	defer func() {
		if r := recover(); r != nil {
			res = Result{Source: src, State: model.ScanError, Reason: fmt.Sprintf("panic: %v", r)}
			emit(events, model.ScanEvent{Source: src, State: model.ScanError, Reason: res.Reason})
		}
	}()

	if ok, reason := c.Available(ctx, env); !ok {
		res = Result{Source: src, State: model.ScanSkipped, Reason: reason}
		emit(events, model.ScanEvent{Source: src, State: model.ScanSkipped, Reason: reason})
		return res
	}

	findings, err := c.Check(ctx, env)
	if err != nil {
		res = Result{Source: src, State: model.ScanError, Reason: err.Error(), Findings: findings}
		emit(events, model.ScanEvent{Source: src, State: model.ScanError, Reason: err.Error()})
		return res
	}

	res = Result{Source: src, State: model.ScanDone, Findings: findings}
	emit(events, model.ScanEvent{Source: src, State: model.ScanDone})
	return res
}

func emit(events chan<- model.ScanEvent, ev model.ScanEvent) {
	if events == nil {
		return
	}
	select {
	case events <- ev:
	default: // never block a scan on a slow/absent consumer
	}
}
