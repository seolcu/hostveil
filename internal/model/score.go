package model

import "math"

// ScoreBreakdown is the 0-100 security score plus its per-axis detail.
// It is pure data so every UI renders it identically.
type ScoreBreakdown struct {
	Overall uint8       `json:"overall"`
	Axes    []ScoreAxis `json:"axes"`
}

// ScoreAxis is one scoring dimension. Applicable is false when the axis's
// domain did not run (e.g. the optional CVE checker was skipped); such an
// axis is reported as N/A and excluded from the overall renormalization
// rather than counted as a misleading perfect 100.
//
// Degraded marks an axis whose domain ran but covered only part of its
// ground (ScanDegraded). Such an axis *is* scored — partial evidence still
// beats none — but its score is drawn from an incomplete picture, so every
// UI must render the flag. An unlabelled 100 on a partial axis is the same
// lie Applicable exists to prevent, just in smaller print.
type ScoreAxis struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Source     Source `json:"source"`
	Applicable bool   `json:"applicable"`
	Degraded   bool   `json:"degraded,omitempty"`
	Score      uint8  `json:"score"`
	Penalty    int    `json:"penalty"`
	MaxPenalty int    `json:"max_penalty"`
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
}

type axisDef struct {
	id     string
	label  string
	source Source
	cap    int
}

// axisDefs maps each detection domain to a scoring axis. A cap is the
// axis's share of the overall score and nothing else — it is purely how
// much this domain matters, never a threshold. The caps sum to 100 so the
// overall is a weighted average of the axes that ran.
var axisDefs = []axisDef{
	{"container", "Container exposure", SourceCompose, 20},
	{"ssh", "SSH hardening", SourceSSH, 18},
	{"firewall", "Host firewall", SourceFirewall, 13},
	{"updates", "Auto-updates", SourceUpdates, 8},
	{"cve", "Vulnerabilities", SourceCVE, 15},
	{"ports", "Exposed services", SourcePorts, 11},
	{"accounts", "Account hygiene", SourceAccounts, 9},
	{"fileperms", "File permissions", SourceFilePerms, 6},
}

// criticalHalves is the anchor of the whole penalty model: one Critical
// finding takes half of whatever credit an axis has left. Every other
// severity follows from it, since a finding's weight is its severity
// penalty over this constant (Critical 8/16 = 0.5, High 0.3125, Medium
// 0.125, Low 0.0625).
const criticalHalves = 16

// unavailableRelief divides the weight of a finding nothing can fix.
//
// It is not zero — the risk is real and claiming otherwise would be the
// same lie as scoring an unscanned domain 100. But it cannot be full
// either: every Debian-based image ships vulnerabilities with no upstream
// patch, so charging them like actionable findings pins the axis at zero
// for a perfectly maintained host. A score you cannot improve by doing
// everything right is not measuring your hardening.
const unavailableRelief = 4

// weight returns the share of an axis's remaining credit a finding takes.
func weight(f Finding) float64 {
	w := float64(f.Severity.Penalty()) / criticalHalves
	if f.Remediation == RemediationUnavailable {
		w /= unavailableRelief
	}
	return w
}

// ScoreReport computes the security score from findings. states reports the
// outcome of each domain's checker; an axis whose domain did not run is
// marked N/A and excluded, and the overall is renormalized over the axes
// that did run so a host without the optional CVE scan is neither penalized
// for it nor handed a falsely perfect vulnerability score. A domain that ran
// but covered only part of its ground is scored with Degraded set.
//
// A nil states map means "every domain ran", the convention used by callers
// that score a bare set of findings with no scan behind them.
func ScoreReport(findings []Finding, states map[Source]ScanState) ScoreBreakdown {
	axes := make([]ScoreAxis, len(axisDefs))
	idxBySource := make(map[Source]int, len(axisDefs))
	for i, def := range axisDefs {
		st, known := states[def.source]
		axes[i] = ScoreAxis{
			ID:         def.id,
			Label:      def.label,
			Source:     def.source,
			Applicable: states == nil || st.Ran(),
			Degraded:   known && st == ScanDegraded,
			Score:      100,
			MaxPenalty: def.cap,
		}
		idxBySource[def.source] = i
	}

	// remaining[i] is the share of axis i still standing. Findings erode it
	// multiplicatively rather than adding up: each one takes a share of what
	// is left, so the tenth Critical still hurts but cannot hurt more than
	// there is left to lose.
	//
	// Summing severities instead — the model this replaces — meant two
	// Criticals exhausted most axes and every finding after that was free.
	// A host with 27 container findings scored identically to one with 3,
	// and the axis was pinned at 0 for anyone running more than a couple of
	// services.
	remaining := make([]float64, len(axes))
	for i := range remaining {
		remaining[i] = 1
	}

	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if f.Fixed {
			continue
		}
		idx, ok := idxBySource[f.Source]
		if !ok {
			continue
		}
		if seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true

		remaining[idx] *= 1 - weight(f)

		axis := &axes[idx]
		switch f.Severity {
		case SeverityCritical:
			axis.Critical++
		case SeverityHigh:
			axis.High++
		case SeverityMedium:
			axis.Medium++
		case SeverityLow:
			axis.Low++
		}
	}

	totalPenalty := 0.0
	ranCapSum := 0
	for i := range axes {
		lost := 1 - remaining[i]
		// Score comes from the fraction directly, not from the rounded
		// penalty. Deriving it from penalty/cap would give a cap-6 axis
		// only seven distinct scores.
		axes[i].Score = uint8(math.Round(100 * remaining[i])) //nolint:gosec // remaining is 0-1
		axes[i].Penalty = int(math.Round(float64(axes[i].MaxPenalty) * lost))
		if axes[i].Applicable {
			totalPenalty += float64(axes[i].MaxPenalty) * lost
			ranCapSum += axes[i].MaxPenalty
		}
	}

	return ScoreBreakdown{Overall: renormalize(totalPenalty, ranCapSum), Axes: axes}
}

// renormalize scales the summed penalty against the caps of the axes that
// actually ran, yielding a 0-100 score even when some axes are N/A.
func renormalize(penalty float64, ranCapSum int) uint8 {
	if ranCapSum <= 0 {
		return 100
	}
	scaled := math.Round(penalty * 100 / float64(ranCapSum))
	if scaled > 100 {
		scaled = 100
	}
	if scaled < 0 {
		scaled = 0
	}
	return uint8(100 - scaled) //nolint:gosec // bounded 0-100
}
