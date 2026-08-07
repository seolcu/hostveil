package model

import (
	"encoding/json"
	"math"
	"sort"
)

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
// Counts is the axis's findings by severity, most severe first, one entry
// per level whether or not any landed there.
//
// It used to be four named int fields and a four-arm switch — the last
// structural four in this package, and the reason a change of scale touched
// the score struct, its JSON, three renderers and their tests. It is a
// projection of AllSeverities now, so a level added or removed reaches every
// consumer without any of them being edited.
type ScoreAxis struct {
	ID         string          `json:"id"`
	Label      string          `json:"label"`
	Source     Source          `json:"source"`
	Applicable bool            `json:"applicable"`
	Degraded   bool            `json:"degraded,omitempty"`
	Score      uint8           `json:"score"`
	Penalty    int             `json:"penalty"`
	MaxPenalty int             `json:"max_penalty"`
	Counts     []SeverityCount `json:"counts"`
}

// SeverityCount is how many findings of one severity landed on an axis.
type SeverityCount struct {
	Severity Severity `json:"severity"`
	N        int      `json:"n"`
}

// Count returns how many findings of one severity landed on the axis.
func (a ScoreAxis) Count(s Severity) int {
	for _, c := range a.Counts {
		if c.Severity == s {
			return c.N
		}
	}
	return 0
}

// Findings is how many landed on the axis in total.
func (a ScoreAxis) Findings() int {
	n := 0
	for _, c := range a.Counts {
		n += c.N
	}
	return n
}

// newCounts builds the zeroed per-severity slots for one axis.
func newCounts() []SeverityCount {
	out := make([]SeverityCount, 0, len(AllSeverities()))
	for _, s := range AllSeverities() {
		out = append(out, SeverityCount{Severity: s})
	}
	return out
}

// UnmarshalJSON reads an axis, folding the four count fields of the old
// severity scale into the three of the new one.
//
// A scan snapshot is read back by the next run, so the previous release's
// axes are on operators' disks with critical/high/medium/low in them.
// Without this they read as an axis with no findings on it, and the domain
// rail would show a scored axis with nothing behind it.
func (a *ScoreAxis) UnmarshalJSON(data []byte) error {
	type axisJSON ScoreAxis // no methods, so no recursion
	var raw struct {
		axisJSON
		Critical *int `json:"critical"`
		High     *int `json:"high"`
		Medium   *int `json:"medium"`
		Low      *int `json:"low"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*a = ScoreAxis(raw.axisJSON)
	if len(a.Counts) > 0 {
		return nil
	}
	legacy := map[Severity]int{}
	for sev, n := range map[Severity]*int{
		SeverityHigh:   raw.Critical,
		SeverityMedium: raw.Medium,
		SeverityLow:    raw.Low,
	} {
		if n != nil {
			legacy[sev] += *n
		}
	}
	if raw.High != nil {
		legacy[SeverityHigh] += *raw.High
	}
	a.Counts = newCounts()
	for i := range a.Counts {
		a.Counts[i].N = legacy[a.Counts[i].Severity]
	}
	return nil
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

// topHalves is the anchor of the whole penalty model: one High finding
// takes half of whatever credit an axis has left. Every other severity
// follows from it, since a finding's weight is its severity penalty over
// this constant (High 8/16 = 0.5, Medium 0.125, Low 0.0625).
//
// Named for the position rather than for the level, because the levels have
// been renamed twice and this constant is about the top of the scale
// whatever the top is called.
const topHalves = 16

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
//
// nth is which instance of this finding's ID it is on this axis, counting
// from 1, and it divides the weight: the same mistake made four times costs
// 1 + 1/2 + 1/3 + 1/4 of one, not four of one.
//
// The instances are not independent risks. A compose file where four services
// all lack `user:` is one mistake written four times, and a self-hoster runs
// many services from one template, so the old arithmetic buried an axis for
// having more services rather than worse ones: four Mediums of a single ID
// took 41% of what was left, and on a twenty-service host the axis was pinned
// at zero by one line missing from a file.
//
// It is not free after the first, either. The tenth instance says the mistake
// is systematic, which is worse than the first — just not ten times worse,
// and the harmonic series is the shape of "worse, with diminishing returns"
// that needs no threshold to argue about.
func weight(f Finding, nth int) float64 {
	w := float64(f.Severity.Penalty()) / topHalves
	if f.Remediation == RemediationUnavailable {
		w /= unavailableRelief
	}
	if nth > 1 {
		w /= float64(nth)
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
			Counts:     newCounts(),
		}
		idxBySource[def.source] = i
	}

	// remaining[i] is the share of axis i still standing. Findings erode it
	// multiplicatively rather than adding up: each one takes a share of what
	// is left, so the tenth High still hurts but cannot hurt more than there
	// is left to lose.
	//
	// Summing severities instead — the model this replaces — meant two
	// top-severity findings exhausted most axes and every finding after that
	// was free.
	// A host with 27 container findings scored identically to one with 3,
	// and the axis was pinned at 0 for anyone running more than a couple of
	// services.
	remaining := make([]float64, len(axes))
	for i := range remaining {
		remaining[i] = 1
	}

	seen := make(map[string]bool, len(findings))
	// Findings grouped by the axis they land on and the ID they share, so a
	// repeat of one mistake can cost less than the first of its kind. Keyed
	// by axis as well as ID: the same ID on two axes is two different
	// mistakes and neither damps the other.
	type group struct {
		axis int
		id   string
	}
	groups := make(map[group][]Finding, len(findings))
	order := make([]group, 0, len(findings))
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

		g := group{idx, f.ID}
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], f)

		axis := &axes[idx]
		for i := range axis.Counts {
			if axis.Counts[i].Severity == f.Severity {
				axis.Counts[i].N++
				break
			}
		}
	}

	for _, g := range order {
		fs := groups[g]
		// Heaviest first, so the divisor lands on the cheaper instances and
		// the answer does not depend on the order the findings arrived in.
		// One ID can carry two severities — a CVE roll-up is the worst level
		// in that image, which differs per image — and without this the same
		// two findings scored differently depending on which was seen first.
		sort.SliceStable(fs, func(i, j int) bool { return weight(fs[i], 1) > weight(fs[j], 1) })
		for n, f := range fs {
			remaining[g.axis] *= 1 - weight(f, n+1)
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
