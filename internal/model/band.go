package model

// Band is the health class of a 0-100 score: which of four ranges it falls
// in, and nothing more. What each band looks like — a meter color, an ANSI
// escape, a phrase — is the renderer's business; where the boundaries sit
// is not, because a boundary is a judgement about what a score means and
// there is only one of those to make.
//
// Careful: a Band runs the opposite way to a Severity. A high score is a
// good host, so BandGood is the top of the range, while SeverityCritical is
// the top of its own. The two vocabularies met in the TUI, where the band
// for a mid-range score and the color for a Medium finding are the same
// palette role, and reading that code as if band meant severity gets the
// direction exactly backwards. The constants are named for the host's
// condition to keep the two apart.
//
// The boundaries were written out four times before this: a switch in the
// TUI, a ternary chain in the dashboard's meter, a second ternary chain in
// the dashboard's overview prose, and a three-arm switch in the CLI. The
// CLI's had only three arms, so it printed a host scoring 10 and a host
// scoring 40 in the same color while the other two showed them a band
// apart.
type Band int

const (
	BandGood     Band = iota // 80-100
	BandFair                 // 50-79
	BandPoor                 // 25-49
	BandCritical             // 0-24
)

type bandDef struct {
	band    Band
	name    string
	min     uint8 // inclusive lower bound
	verdict string
}

// bandDefs is ordered best-first; BandFor walks it and takes the first
// band whose floor the score clears. The last row must have min 0 so the
// walk always terminates on a real band.
var bandDefs = []bandDef{
	{BandGood, "good", 80, "in good shape"},
	{BandFair, "fair", 50, "middling"},
	{BandPoor, "poor", 25, "exposed"},
	{BandCritical, "critical", 0, "wide open"},
}

// BandFor classifies a 0-100 score.
func BandFor(score uint8) Band {
	for _, d := range bandDefs {
		if score >= d.min {
			return d.band
		}
	}
	return BandCritical
}

// String returns the stable lowercase band name.
func (b Band) String() string {
	for _, d := range bandDefs {
		if d.band == b {
			return d.name
		}
	}
	return "critical"
}

// Bands lists every band, best-first, with its inclusive lower bound. It
// exists so a renderer can build its own band→appearance table without
// copying the boundaries out again.
func Bands() []Band {
	out := make([]Band, len(bandDefs))
	for i, d := range bandDefs {
		out[i] = d.band
	}
	return out
}

// Verdict is the band said out loud: the half-sentence a UI completes with
// "This host is …". It is a phrase and not a color, so by the rule at the
// top of this file it looks like the renderer's business — but two
// renderers now need the same words, and a phrase paired with the wrong
// band is the same defect as a meter painted the wrong color. The dashboard
// held these four strings and the terminal would have had to copy them.
func (b Band) Verdict() string {
	for _, d := range bandDefs {
		if d.band == b {
			return d.verdict
		}
	}
	return "unscored"
}

// Min returns the band's inclusive lower bound.
func (b Band) Min() uint8 {
	for _, d := range bandDefs {
		if d.band == b {
			return d.min
		}
	}
	return 0
}
