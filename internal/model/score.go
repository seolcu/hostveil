package model

import "math"

// ScoreBreakdown is the 0-100 security score plus its per-axis detail.
// It is pure data so every UI renders it identically.
type ScoreBreakdown struct {
	Overall uint8       `json:"overall"`
	Axes    []ScoreAxis `json:"axes"`
	// Applicable is false when no domain ran at all, in which case Overall
	// carries no information and must not be shown as a number.
	//
	// The per-axis Applicable flag exists so a skipped domain is reported N/A
	// rather than 100; without this the same lie survived in the aggregate.
	// With every axis excluded there is nothing to renormalize over, and the
	// arithmetic falls out at a perfect 100 — a host nobody could look at,
	// scored as flawless. It takes an unusual host (no package manager, no
	// readable sshd_config, no firewall tooling, no Docker) but "unusual" is
	// not "impossible", and this is the one number the whole tool is judged
	// on.
	Applicable bool `json:"applicable"`
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

// axisDefsFromSources reads the axis columns out of sourceDefs.
func axisDefsFromSources() []axisDef {
	return columnOf(sourceDefs, func(d sourceDef) axisDef {
		return axisDef{id: d.axisID, label: d.axisLabel, source: d.source, cap: d.cap}
	})
}

// axisDefs is the scoring axes, one per detection domain, in the order
// sourceDefs declares them.
//
// It used to be a hand-written table of its own — a fifth record per
// domain, in a second file, keyed by the same constant as the four in
// source.go. Nothing tied the two together, so adding a domain meant
// remembering both, and the axis order and the scan order agreed only
// because someone kept them agreeing.
//
// The numbers now live in sourceDefs' cap column; what follows is the
// argument behind them, which stays here because a cap is a claim about
// weight rather than a fact about a domain's identity.
//
// A cap is the axis's share of the overall score and nothing else — it is
// purely how much this domain matters, never a threshold. The caps sum to
// 100 so the overall is a weighted average of the axes that ran.
//
// "agent" ties with "ports" deliberately: both describe a network service
// that should not be reachable. The agent domain's worst case is strictly
// worse — an unauthenticated gateway is remote code execution as a real
// user — but it applies to far fewer hosts, and it is N/A-excluded entirely
// on any host with no agent runtime installed. So the generous cap costs a
// typical host nothing and carries real weight where it applies.
//
// "sysctl" ties with "fileperms" deliberately too: both are quiet local-
// hardening backstops — neither is the hole an attacker comes in through,
// each is what stops a foothold from becoming root.
//
// "dockerd" ties with "accounts" and "updates", and the tie is the argument:
// like account hygiene it is a small rule set where one member is
// catastrophic and the rest are hygiene, and like both it is excluded
// entirely on a host it does not apply to. Six axes gave up a point to fund
// it. "container" gave two because it was the only place any Docker risk
// landed and was implicitly priced to cover the daemon as well; it no longer
// has to, and compose findings are now strictly about what a service
// declares. "ssh" gave one because on a host running Docker the daemon socket
// is a second remote-administration channel with SSH's blast radius and none
// of its hardening. "cve" gave one because both are Docker-conditional and an
// open API hands over every container today, while an image's patch level is
// a slower problem. "firewall" gave one because firewall.docker-bypass
// already says the daemon walks through the host firewall. "ports" gave one
// because this axis takes custody of the most dangerous port a Docker host
// can publish — one the port table could never have judged, since the number
// alone does not say whether TLS verification is in force. "agent" gave one
// because its generous cap was argued from being N/A on most hosts, and that
// argument now has a second claimant.
//
// "systemd" sits just under "accounts", "updates" and "dockerd", and the gap
// is the argument. It covers the same ground for a unit-started service that
// "container" covers for a compose one — can it gain privileges, can it write
// outside its own data, can it read every home directory — so on a host that
// runs its services natively it is doing the work "container" does elsewhere.
// It is one step below that band because none of its findings is by itself an
// entry: each one widens what a compromise reaches rather than granting it.
// Six axes funded it, each giving one. "container" and "ssh" gave from the
// top because they are the only two large enough that a point does not change
// what they can express. "cve", "ports", "firewall" and "agent" gave because
// each already had a share argued as generous — and because a service running
// unsandboxed is the step *after* every one of them: the exposed port, the
// unpatched image, and the bypassed firewall all end at a process, and this
// axis is about what that process can then touch.
var axisDefs = axisDefsFromSources()

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

	return ScoreBreakdown{
		Overall:    renormalize(totalPenalty, ranCapSum),
		Axes:       axes,
		Applicable: ranCapSum > 0,
	}
}

// renormalize scales the summed penalty against the caps of the axes that
// actually ran, yielding a 0-100 score even when some axes are N/A.
func renormalize(penalty float64, ranCapSum int) uint8 {
	if ranCapSum <= 0 {
		// Callers must check ScoreBreakdown.Applicable rather than reading
		// this; the value is arbitrary because there is nothing to average.
		return 0
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
