package model

import (
	"strings"
	"testing"
)

// The sentence is the whole reason this type carries a Message: four
// surfaces phrased it themselves and each dropped a different field.
func TestBatchOutcomeSummary(t *testing.T) {
	score := ScoreBreakdown{Overall: 64, Applicable: true}

	for name, tc := range map[string]struct {
		out     BatchOutcome
		want    []string
		wantNot []string
	}{
		"all applied": {
			out:     BatchOutcome{Applied: []string{"a", "b"}, NewScore: score},
			want:    []string{"Applied 2", "New score: 64/100."},
			wantNot: []string{"skipped", "failed", "Interrupted"},
		},
		"skipped and failed are both named": {
			out: BatchOutcome{
				Applied: []string{"a"}, Skipped: []string{"b", "c"},
				Failed: map[string]string{"d": "boom"}, NewScore: score,
			},
			want: []string{"Applied 1", "skipped 2", "failed 1"},
		},
		// The bug this replaced: the dashboard's batch path counted these
		// three and never mentioned the interruption, so a batch cut short
		// read exactly like one that completed.
		"interrupted says how many were never reached": {
			out: BatchOutcome{
				Applied: []string{"a", "b"}, Skipped: []string{"c", "d", "e"},
				Interrupted: true, NewScore: score,
			},
			want: []string{"Applied 2", "skipped 3", "Interrupted — 3 of 5 were never attempted."},
		},
		// The other half: a failure must never be silent, which is what the
		// fix-all path did by reporting only the applied count.
		"a failure is never silent": {
			out: BatchOutcome{
				Applied: []string{"a"}, Failed: map[string]string{"b": "boom"}, NewScore: score,
			},
			want: []string{"failed 1"},
		},
		"nothing applied at all": {
			out:  BatchOutcome{Skipped: []string{"a"}, NewScore: score},
			want: []string{"Applied 0", "skipped 1"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := tc.out.Summary()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("Summary() = %q, want it to contain %q", got, w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(got, w) {
					t.Errorf("Summary() = %q, must not mention %q", got, w)
				}
			}
		})
	}
}

// The total in "3 of 5" is derived rather than passed in, which only works
// because every finding handed to a batch lands in exactly one bucket.
func TestBatchSummaryTotalCoversEveryBucket(t *testing.T) {
	out := BatchOutcome{
		Applied:     []string{"a", "b"},
		Skipped:     []string{"c"},
		Failed:      map[string]string{"d": "boom", "e": "boom"},
		Interrupted: true,
	}
	if got := out.Summary(); !strings.Contains(got, "1 of 5 were never attempted") {
		t.Errorf("Summary() = %q; the total must count applied + skipped + failed", got)
	}
}

// Summary states what happened and stops. "press h" and "hostveil history"
// are directions to a place only one interface has.
func TestBatchSummaryCarriesNoInterfaceDirections(t *testing.T) {
	out := BatchOutcome{Applied: []string{"a"}, Interrupted: true}
	got := out.Summary()
	for _, leak := range []string{"press", "hostveil", "history", "click", "button"} {
		if strings.Contains(strings.ToLower(got), leak) {
			t.Errorf("Summary() = %q leaks the interface-specific direction %q", got, leak)
		}
	}
}
