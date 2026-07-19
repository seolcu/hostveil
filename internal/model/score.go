package model

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

// axisDefs maps each detection domain to a scoring axis. The caps sum to
// 100 so, when every axis runs, the score is a plain 100 − Σpenalty.
var axisDefs = []axisDef{
	{"container", "Container exposure", SourceCompose, 22},
	{"ssh", "SSH hardening", SourceSSH, 18},
	{"firewall", "Host firewall", SourceFirewall, 14},
	{"updates", "Auto-updates", SourceUpdates, 8},
	{"cve", "Vulnerabilities", SourceCVE, 10},
	{"ports", "Exposed services", SourcePorts, 12},
	{"accounts", "Account hygiene", SourceAccounts, 10},
	{"fileperms", "File permissions", SourceFilePerms, 6},
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

		axis := &axes[idx]
		axis.Penalty += f.Severity.Penalty()
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

	totalPenalty := 0
	ranCapSum := 0
	for i := range axes {
		if axes[i].Penalty > axes[i].MaxPenalty {
			axes[i].Penalty = axes[i].MaxPenalty
		}
		axes[i].Score = axisScore(axes[i].Penalty, axes[i].MaxPenalty)
		if axes[i].Applicable {
			totalPenalty += axes[i].Penalty
			ranCapSum += axes[i].MaxPenalty
		}
	}

	return ScoreBreakdown{Overall: renormalize(totalPenalty, ranCapSum), Axes: axes}
}

// renormalize scales the summed penalty against the caps of the axes that
// actually ran, yielding a 0-100 score even when some axes are N/A.
func renormalize(penalty, ranCapSum int) uint8 {
	if ranCapSum <= 0 {
		return 100
	}
	scaled := penalty * 100 / ranCapSum
	if scaled > 100 {
		scaled = 100
	}
	return uint8(100 - scaled) //nolint:gosec // bounded 0-100
}

func axisScore(penalty, maxPenalty int) uint8 {
	if maxPenalty <= 0 || penalty <= 0 {
		return 100
	}
	if penalty >= maxPenalty {
		return 0
	}
	return uint8(100 - penalty*100/maxPenalty) //nolint:gosec // bounded 0-100
}
