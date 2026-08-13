package uitest

import (
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// Every domain has to be accounted for in the host the website's screenshots
// show, and a domain that did not run has to say why.
//
// This is the test that was missing when SourceDockerd fell out of the
// fixture. A Source absent from the states map reads as the zero-value
// ScanPending, so the axis renders N/A — and with no matching DomainResult
// there is no reason beside it. Both published pictures carried a domain in
// that state, which is precisely the "I could not look, and I will not say
// why" the rail was built to prevent.
//
// Walking AllSources rather than the fixture's own keys is what makes a new
// domain loud instead of silent.
func TestPublishedReportAccountsForEveryDomain(t *testing.T) {
	rep := PublishedReport()

	scored := map[model.Source]model.ScoreAxis{}
	for _, ax := range rep.Score.Axes {
		scored[ax.Source] = ax
	}
	explained := map[model.Source]model.DomainResult{}
	for _, d := range rep.Domains {
		explained[d.Source] = d
	}

	for _, src := range model.AllSources() {
		ax, ok := scored[src]
		if !ok {
			t.Errorf("%s has no axis in the published report", src)
			continue
		}
		if ax.Applicable {
			continue
		}
		d, ok := explained[src]
		if !ok {
			t.Errorf("%s renders N/A in both published screenshots with no DomainResult to explain it", src)
			continue
		}
		if d.Reason == "" {
			t.Errorf("%s did not run and carries no reason", src)
		}
	}
}

// A domain the fixture marks as not-done must still be one hostveil has. An
// exception left behind after a domain is renamed would sit in the map doing
// nothing, and the screenshots would quietly lose the notice it was there to
// produce.
func TestPublishedReportHasNoDomainsHostveilDoesNotHave(t *testing.T) {
	known := map[model.Source]bool{}
	for _, src := range model.AllSources() {
		known[src] = true
	}
	for _, d := range PublishedReport().Domains {
		if !known[d.Source] {
			t.Errorf("the published report explains %q, which is not a domain", d.Source)
		}
	}
}
