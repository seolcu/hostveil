package web

import (
	"sync"

	"github.com/seolcu/hostveil/internal/model"
)

// progressTracker keeps a per-domain snapshot of the scan in flight.
//
// The engine's progress emit is deliberately lossy — a full channel buffer
// drops events rather than stall a checker — so the consumer keeps
// latest-state-per-domain instead of replaying a stream. A dropped event is
// invisible as long as a later one lands, and each domain's final event
// always does because the drain goroutine empties the channel faster than
// checkers finish.
type progressTracker struct {
	mu      sync.Mutex
	running bool
	domains map[model.Source]model.ScanEvent
}

// begin marks a scan as started and clears the previous snapshot. It
// returns false when one is already running, which is what turns a second
// rescan click into a 409 rather than a queued multi-minute scan.
func (p *progressTracker) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return false
	}
	p.running = true
	p.domains = map[model.Source]model.ScanEvent{}
	return true
}

func (p *progressTracker) update(ev model.ScanEvent) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.domains == nil {
		p.domains = map[model.Source]model.ScanEvent{}
	}
	p.domains[ev.Source] = ev
}

func (p *progressTracker) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
}

// domainProgress is one domain's latest state, shaped for the client.
type domainProgress struct {
	Source string `json:"source"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// snapshot returns whether a scan is running and each seen domain's latest
// state, in the stable AllSources order so the client's list does not
// reshuffle between polls.
func (p *progressTracker) snapshot() (bool, []domainProgress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []domainProgress{}
	for _, src := range model.AllSources() {
		if ev, ok := p.domains[src]; ok {
			out = append(out, domainProgress{Source: src.String(), State: ev.State.String(), Reason: ev.Reason})
		}
	}
	return p.running, out
}
