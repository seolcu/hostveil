package main

import (
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The order the checkers are registered in is the third copy of the domain
// order, and until now it was the only one with nothing holding it in
// place.
//
// It is not cosmetic. Registry.Run writes its results by registry index, so
// this list — not model.AllSources — is what orders Report.Domains, which
// is what the CLI prints as its per-domain status block. The other two
// copies were merged into sourceDefs and can no longer disagree with each
// other; this one still can, and a registration slipped into the wrong
// position would show a user their domains in one order and their scoring
// axes in another, with no error anywhere.
//
// It also catches the plainer mistake: a checker package written, tested,
// and never registered. buildEngine is the only place that turns a checker
// into something that runs, and a domain missing from here reports nothing
// while its axis reports N/A — which reads as "not installed", not as "we
// forgot to call it".
func TestCheckerRegistrationMatchesSourceOrder(t *testing.T) {
	var registered []model.Source
	for _, c := range buildRegistry().Checkers() {
		registered = append(registered, c.Source())
	}

	want := model.AllSources()
	if len(registered) != len(want) {
		t.Fatalf("buildEngine registers %d checkers, but %d domains are declared: got %v, want %v",
			len(registered), len(want), registered, want)
	}
	for i := range want {
		if registered[i] != want[i] {
			t.Errorf("checker %d is %q, but domain %d is %q — registration order must match sourceDefs",
				i, registered[i], i, want[i])
		}
	}
}
