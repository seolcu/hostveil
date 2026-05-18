package domain

type ScoreReport struct {
	Overall          uint8
	AxisScores       map[Axis]uint8
	SeverityCounts   map[Severity]int
}

func (s *ScoreReport) Grade() string {
	switch {
	case s.Overall >= 90:
		return "Good"
	case s.Overall >= 70:
		return "Fair"
	case s.Overall >= 50:
		return "Poor"
	case s.Overall >= 30:
		return "Bad"
	default:
		return "Critical"
	}
}
