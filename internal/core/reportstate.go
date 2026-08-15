package core

import (
	"slices"
	"sync"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
)

// reportState is the engine's memory of the last scan: the report itself,
// whether one has run, and how it differed from the one before.
//
// It is its own type because it is its own object. Five of the Engine's
// fields existed only to serve it, and every method that touched them
// touched nothing else — no registry, no store, no host. Sharing a body
// with the rest of the engine bought nothing and cost the one invariant
// that matters here.
//
// That invariant is the copy in snapshot. Report is a struct but Findings
// is a slice, so handing one back by value hands the caller the same
// backing array this type keeps mutating: markFixed writes Fixed on those
// elements under the lock while the caller reads them outside it. The web
// dashboard hit exactly that, and `go test -race` reported a write in
// markFixed against a concurrent read in json.Encoder serving /api/result.
// While the state was five loose fields the copy was a thing to remember at
// each read; behind this type there is one way out and it copies.
type reportState struct {
	mu        sync.RWMutex
	current   model.Report
	hasRun    bool
	lastDelta model.Delta
}

// snapshot returns a copy of the current report and whether a scan has run.
func (s *reportState) snapshot() (model.Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r := s.current
	r.Findings = slices.Clone(s.current.Findings)
	return r, s.hasRun
}

// delta returns how the last scan differed from the one before it.
func (s *reportState) delta() model.Delta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastDelta
}

// replace installs the result of a completed scan.
func (s *reportState) replace(r model.Report, d model.Delta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = r
	s.hasRun = true
	s.lastDelta = d
}

// markFixed marks the target finding fixed, and records whether the fix is
// in force yet.
//
// pending is the caller's answer to "has the host changed", and it is passed
// in rather than derived here because only the apply path knows: it holds the
// action, and Action.TakesEffectOn is where a fix declares that its artifact
// is not what the host is running from. See model.Finding.Pending.
//
// The match is on the key alone. It used to require !f.Fixed as well, which
// was harmless while this only ever set a flag one way, and is not once the
// call can arrive a second time for the same finding — ApplyFix re-marks after
// a re-check comes back still-present, and that call has to be able to land.
//
// It used to return "the list of additional findings marked (currently
// none)" against a planned cross-finding cascade, and FixOutcome carried
// that list to the UIs as `also_fixed`. Nothing ever populated it and no
// interface ever read it, so the field promised a behaviour the engine did
// not have; both are gone. If a cascade is ever built, it should be built
// with the thing that reports it, not ahead of it.
func (s *reportState) markFixed(target model.Finding, pending bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.current.Findings {
		f := &s.current.Findings[i]
		if f.Key() == target.Key() {
			f.Fixed = true
			// Never downgraded: a second call that learned nothing must not
			// erase what the first one established. See the monotonicity rule
			// on Engine.ApplyFix.
			f.Pending = f.Pending || pending
		}
	}
}

// unmarkFixed clears the Fixed flag on the finding a checkpoint fixed, so
// it reappears in every UI's active list. It matches on the full
// source|id|service key where the checkpoint has one, falling back to the
// bare finding ID for checkpoints written before FindingKey existed.
func (s *reportState) unmarkFixed(cp history.Checkpoint) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var unfixed []string
	for i := range s.current.Findings {
		f := &s.current.Findings[i]
		if !f.Fixed {
			continue
		}
		if cp.FindingKey != "" && f.Key() != cp.FindingKey {
			continue
		}
		if cp.FindingKey == "" && f.ID != cp.FindingID {
			continue
		}
		f.Fixed = false
		// Both flags, so the finding goes back to plainly standing. Rolling
		// back a pending fix leaves the score where it was — it was already
		// being charged — which is correct and is why Unfixed, not the score,
		// is the honest signal that anything happened.
		f.Pending = false
		unfixed = append(unfixed, f.ID)
	}
	return unfixed
}

// rescore recomputes the score from the findings as they now stand, which
// is what makes an applied or rolled-back fix move the number.
func (s *reportState) rescore() model.ScoreBreakdown {
	s.mu.Lock()
	defer s.mu.Unlock()
	states := make(map[model.Source]model.ScanState, len(s.current.Domains))
	for _, d := range s.current.Domains {
		states[d.Source] = d.State
	}
	s.current.Score = model.ScoreReport(s.current.Findings, states)
	return s.current.Score
}
