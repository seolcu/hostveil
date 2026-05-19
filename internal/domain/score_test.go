package domain

import "testing"

func TestScoreGrade(t *testing.T) {
	tests := []struct {
		score uint8
		want  string
	}{
		{95, "Good"},
		{80, "Fair"},
		{60, "Poor"},
		{40, "Bad"},
		{20, "Critical"},
		{0, "Critical"},
	}
	for _, tt := range tests {
		s := ScoreReport{Overall: tt.score}
		if s.Grade() != tt.want {
			t.Errorf("Grade(%d) = %q, want %q", tt.score, s.Grade(), tt.want)
		}
	}
}
