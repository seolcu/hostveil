package clirender

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestPointsLeftLine(t *testing.T) {
	if got := pointsLeftLine(model.PointsLeft{}); got != "" {
		t.Errorf("nothing left should print nothing, got %q", got)
	}
	got := pointsLeftLine(model.PointsLeft{Pending: 3, PendingCount: 1, Manual: 20, ManualCount: 3, Unavailable: 7, UnavailableCount: 1})
	for _, want := range []string{"+3 after restarts (1 fix)", "20 to fix by hand (3 findings)", "7 with no fix yet (1 finding)"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is missing %q", got, want)
		}
	}
}
