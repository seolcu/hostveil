package core

import (
	"context"
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// PlannedDomains is a promise about a scan that has not happened yet, and the
// only thing that can break it is the selection drifting from the one ScanWith
// applies. So the test runs the scan and compares the plan against the domains
// that actually reported.
//
// A plan that over-counts is the failure worth naming: the terminal draws a
// bar out of it, and a bar that reaches eleven of twelve and stops there reads
// as a hang — which is precisely the state the progress display was added to
// rule out.
func TestThePlanNamesTheDomainsTheScanActuallyRuns(t *testing.T) {
	sources := []model.Source{model.SourceSSH, model.SourceFirewall, model.SourceSysctl, model.SourceUpdates}
	checkers := make([]check.Checker, 0, len(sources))
	for _, src := range sources {
		checkers = append(checkers, &stubChecker{src: src})
	}
	e := New(Config{Registry: check.NewRegistry(checkers...), Store: history.NewStore(t.TempDir())})

	for _, tc := range []struct {
		name string
		opts ScanOptions
	}{
		{"a full scan", ScanOptions{}},
		{"one domain", ScanOptions{Only: []model.Source{model.SourceSysctl}}},
		{"two domains", ScanOptions{Only: []model.Source{model.SourceUpdates, model.SourceSSH}}},
		{"a domain this engine does not have", ScanOptions{Only: []model.Source{model.SourceCVE}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			planned := e.PlannedDomains(tc.opts)

			events := make(chan model.ScanEvent, 64)
			done := make(chan []model.Source)
			go func() {
				var terminal []model.Source
				for ev := range events {
					if ev.State != model.ScanRunning {
						terminal = append(terminal, ev.Source)
					}
				}
				done <- terminal
			}()
			e.ScanWith(context.Background(), events, tc.opts)
			close(events)
			ran := <-done

			slices.Sort(planned)
			slices.Sort(ran)
			if !slices.Equal(planned, ran) {
				t.Errorf("planned %v, ran %v — a progress bar built on this plan would stop short or overrun", planned, ran)
			}
		})
	}
}

// And the order is the registry's, because that is the order the terminal
// lists the domains in while they are still waiting. Sorting them somewhere
// else would reorder the screen for no reason a reader could see.
func TestThePlanKeepsRegistryOrder(t *testing.T) {
	sources := []model.Source{model.SourceUpdates, model.SourceSSH, model.SourceSysctl}
	checkers := make([]check.Checker, 0, len(sources))
	for _, src := range sources {
		checkers = append(checkers, &stubChecker{src: src})
	}
	e := New(Config{Registry: check.NewRegistry(checkers...), Store: history.NewStore(t.TempDir())})
	if got := e.PlannedDomains(ScanOptions{}); !slices.Equal(got, sources) {
		t.Errorf("PlannedDomains = %v, want the registry's own order %v", got, sources)
	}
}
