package model

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
)

// ScoreBreakdown is the 0-100 security score plus its per-axis detail.
// It is pure data so every UI renders it identically.
type ScoreBreakdown struct {
	Overall uint8       `json:"overall"`
	Axes    []ScoreAxis `json:"axes"`
	// Applicable is false when no domain ran at all, in which case Overall
	// carries no information and must not be shown as a number.
	//
	// The per-axis Applicable flag exists so a skipped domain is reported N/A; without this the same lie survived in the aggregate.
	// With every axis excluded there is nothing to renormalize over, and the
	// arithmetic falls out at a perfect 100; a host the scan could not look at,
	// scored as flawless. It takes an unusual host (no package manager, no
	// readable sshd_config, no firewall tooling, no Docker) but "unusual" is
	// not "impossible", and this is the one number the whole tool is judged
	// on.
	Applicable bool `json:"applicable"`

	// AfterFixes is Overall recomputed with every fix Hostveil offers (Auto
	// and Review both) treated as applied.
	//
	// It answers a question the score alone cannot, and that an operator
	// reasonably reads the score as already answering. A host whose container
	// axis sits at 2 after `fix --all` looks like a tool that did nothing,
	// when what happened is that the findings still standing are
	// Manual by design: a Docker socket mounted into Portainer, a second UID 0
	// account, host networking. The number was right and it was being read as
	// a verdict on the effort.
	//
	// The alternative was to charge Manual findings less, and it is the wrong
	// trade in the exact place it looks tempting. Manual means Hostveil will
	// not do it unattended. It can still be done: the operator can
	// delete the account or drop the socket mount this afternoon. Discounting
	// a risk the operator is fully able to remove is the flattery this
	// scoring model was rebuilt to refuse, and it is no longer a special
	// case, since RemediationUnavailable findings (no upstream patch exists)
	// are charged in full too, for the same reason.
	//
	// So the risk is charged in full and the headroom is published beside it.
	// Named for what it is: the difference between
	// this and 100 is what Hostveil will not fix for you, which is not the
	// same as what cannot be fixed.
	//
	// Equal to Overall when nothing is fixable, which is the case every UI
	// must render as nothing at all.
	AfterFixes uint8 `json:"after_fixes"`
	// AfterSafeFixes is the overall with only the Auto fixes treated as
	// applied and in force: what "fix all safe" leaves. Every UI puts this
	// number beside the score, because it is the one the big button
	// delivers; AfterFixes adds the Review fixes, which need a person, and
	// PointsLeft.Review is the difference.
	AfterSafeFixes uint8 `json:"after_safe_fixes"`

	// Left says where the points between the score and 100 are, by what it
	// takes to win them back. See PointsLeft.
	Left PointsLeft `json:"left"`
}

// PointsLeft splits the points a score is short of 100 by what the operator
// can do about each part.
//
// AfterFixes answers "how far do the offered fixes go". Left answers the
// question a reader asks next, looking at a 58 after every fix: what is the
// rest, and is any of it theirs to win. Without it a remaining gap reads as
// the tool failing.
//
// Pending is inside the gap between the score and AfterFixes: fixes already
// applied that take effect after a restart. Manual and Unavailable are the
// gap between AfterFixes and 100. They are attributed in that order, each
// measured with the previous part already won, so Manual + Unavailable is
// exactly 100 - AfterFixes and no point is counted twice.
type PointsLeft struct {
	// Pending is the points that return once applied fixes take effect.
	Pending      uint8 `json:"pending"`
	PendingCount int   `json:"pending_count"`
	// Review is the points the Review fixes add on top of the safe ones:
	// AfterFixes - AfterSafeFixes. Each has a button, behind a warning a
	// person reads first.
	Review      uint8 `json:"review"`
	ReviewCount int   `json:"review_count"`
	// Manual is the points held by findings Hostveil explains and leaves for
	// the operator to fix by hand (RemediationManual, and anything not
	// classified at all).
	Manual      uint8 `json:"manual"`
	ManualCount int   `json:"manual_count"`
	// Unavailable is the points held by findings with no fix published yet,
	// such as a CVE with no upstream patch.
	Unavailable      uint8 `json:"unavailable"`
	UnavailableCount int   `json:"unavailable_count"`
}

// Any reports whether any part of PointsLeft is worth showing.
func (p PointsLeft) Any() bool {
	return p.Pending > 0 || p.Review > 0 || p.Manual > 0 || p.Unavailable > 0
}

// ScoreAxis is one scoring dimension. Applicable is false when the axis's
// domain did not run (e.g. the optional CVE checker was skipped); such an
// axis is reported as N/A and excluded from the overall renormalization
// so it never counts as a misleading perfect 100.
//
// Degraded marks an axis whose domain ran but covered only part of its
// ground (ScanDegraded). Such an axis *is* scored (partial evidence still
// beats none) but its score is drawn from an incomplete picture, so every
// UI must render the flag. An unlabelled 100 on a partial axis is the same
// lie Applicable exists to prevent, just in smaller print.
// Counts is the axis's findings by severity, most severe first, one entry
// per level whether or not any landed there.
//
// It used to be four named int fields and a four-arm switch: the last
// structural four in this package, and the reason a change of scale touched
// the score struct, its JSON, three renderers and their tests. It is a
// projection of AllSeverities now, so a level added or removed reaches every
// consumer without any of them being edited.
type ScoreAxis struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Source     Source `json:"source"`
	Applicable bool   `json:"applicable"`
	Degraded   bool   `json:"degraded,omitempty"`
	Score      uint8  `json:"score"`
	// AfterFixes is Score with every fix Hostveil offers on this axis
	// treated as applied. See ScoreBreakdown.AfterFixes; the per-axis one is
	// what makes the aggregate actionable, because it says *where* the
	// headroom is.
	AfterFixes uint8 `json:"after_fixes"`
	// AfterSafeFixes is this axis with only the Auto fixes applied.
	AfterSafeFixes uint8           `json:"after_safe_fixes"`
	Penalty        int             `json:"penalty"`
	MaxPenalty     int             `json:"max_penalty"`
	Counts         []SeverityCount `json:"counts"`
}

// Headroom is the overall score's version of ScoreAxis.Headroom, and follows
// the same rule for the same reason: nothing to show when the fixes would not
// move it, and nothing to show when no domain ran.
func (b ScoreBreakdown) Headroom() (uint8, bool) {
	if !b.Applicable || b.AfterSafeFixes <= b.Overall {
		return 0, false
	}
	return b.AfterSafeFixes, true
}

// ValueText is the axis's score as every interface writes it: "N/A" when the
// domain did not run, the score with a "~" when it ran but covered only part
// of its ground, and the bare number otherwise.
//
// It is here because it used to be in each renderer;
// the same three-arm decision in the CLI, twice in the terminal's
// arrangements, once more in its axes strip, and again in the dashboard's
// JavaScript. Nothing compared them.
//
// The "~" is the part that matters. A degraded axis is scored from an
// incomplete picture, and an unmarked score on one is the same lie
// Applicable exists to prevent, just in smaller print: it says a domain
// vouches for ground it never looked at. One renderer silently dropping the
// marker would have looked like a cleaner number.
//
// Colour stays with the renderers. A terminal has a palette, a stylesheet has
// a class, and neither belongs in a value type.
func (a ScoreAxis) ValueText() string {
	switch {
	case !a.Applicable:
		return "N/A"
	case a.Degraded:
		return strconv.Itoa(int(a.Score)) + "~"
	default:
		return strconv.Itoa(int(a.Score))
	}
}

// ValueTextWidth is the widest ValueText can be: "100~", a degraded axis on a
// domain that ran, covered only part of its ground, and found nothing in the
// part it covered.
//
// It is here because a terminal budgets columns, and every renderer that lays
// the axis values out in a column had picked the number by hand; all of them
// picking three, because three is what a score looks like and the widest case
// needs a host that is both partially scanned and clean on the part that was
// scanned. The consequence was not a cosmetic one: the strip composed a row
// one column past the terminal, the frame clipped it, and what the clip cut
// off was the "~", so a degraded axis read as a clean 100, which is the exact
// lie the marker exists to prevent.
const ValueTextWidth = 4

// Headroom is what this axis becomes once every fix Hostveil offers on it is
// applied, and whether that is worth showing at all.
//
// The second return matters: every interface hides the figure
// under the same two conditions; nothing when it equals the score, because
// an arrow pointing where it started says the fixes are worth nothing, and
// nothing beside an N/A axis, because a number there is a claim about a
// domain the scan never looked at. Those two conditions were written out in each
// renderer and held together only by a test that greps for them.
func (a ScoreAxis) Headroom() (uint8, bool) {
	if !a.Applicable || a.AfterSafeFixes <= a.Score {
		return 0, false
	}
	return a.AfterSafeFixes, true
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
// It used to be a hand-written table of its own: a fifth record per
// domain, in a second file, keyed by the same constant as the four in
// source.go. Nothing tied the two together, so adding a domain meant
// remembering both, and the axis order and the scan order agreed only
// because someone kept them agreeing.
//
// The numbers now live in sourceDefs' cap column; what follows is the
// argument behind them, which stays here because a cap is a claim about
// weight.
//
// A cap is the axis's share of the overall score and nothing else: it is
// purely how much this domain matters, never a threshold. The caps sum to
// 100 so the overall is a weighted average of the axes that ran.
//
// "agent" ties with "ports": both describe a network service
// that should not be reachable. The agent domain's worst case is strictly
// worse (an unauthenticated gateway is remote code execution as a real
// user) but it applies to far fewer hosts, and it is N/A-excluded entirely
// on any host with no agent runtime installed. So the generous cap costs a
// typical host nothing and carries real weight where it applies.
//
// "sysctl" ties with "fileperms" too: both are quiet local-
// hardening backstops; neither is the hole an attacker comes in through,
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
// can publish: one the port table could never have judged, since the number
// alone does not say whether TLS verification is in force. "agent" gave one
// because its generous cap was argued from being N/A on most hosts, and that
// argument now has a second claimant.
//
// "systemd" sits just under "accounts", "updates" and "dockerd", and the gap
// is the argument. It covers the same ground for a unit-started service that
// "container" covers for a compose one (can it gain privileges, can it write
// outside its own data, can it read every home directory) so on a host that
// runs its services natively it is doing the work "container" does elsewhere.
// It is one step below that band because none of its findings is by itself an
// entry: each one widens what a compromise reaches.
// Six axes funded it, each giving one. "container" and "ssh" gave from the
// top because they are the only two large enough that a point does not change
// what they can express. "cve", "ports", "firewall" and "agent" gave because
// each already had a share argued as generous, and because a service running
// unsandboxed is the step *after* every one of them: the exposed port, the
// unpatched image, and the bypassed firewall all end at a process, and this
// axis is about what that process can then touch.
var axisDefs = axisDefsFromSources()

// topHalves is the anchor of the whole penalty model: one High finding
// takes half of whatever credit an axis has left. Every other severity
// follows from it, since a finding's weight is its severity penalty over
// this constant (High 8/16 = 0.5, Medium 0.125, Low 0.0625).
//
// Named for the position, because the levels have
// been renamed twice and this constant is about the top of the scale
// whatever the top is called.
const topHalves = 16

// weight returns the share of an axis's remaining credit a finding takes.
//
// nth is which instance of this finding's ID it is on this axis, counting
// from 1, and it divides the weight: the same mistake made four times costs
// 1 + 1/2 + 1/3 + 1/4 of one.
//
// The instances are not independent risks. A compose file where four services
// all lack `user:` is one mistake written four times, and a self-hoster runs
// many services from one template, so the old arithmetic buried an axis for
// having more services: four Mediums of a single ID
// took 41% of what was left, and on a twenty-service host the axis was pinned
// at zero by one line missing from a file.
//
// It is not free after the first, either. The tenth instance says the mistake
// is systematic, which is worse than the first: just not ten times worse,
// and the harmonic series is the shape of "worse, with diminishing returns"
// that needs no threshold to argue about.
func weight(f Finding, nth int) float64 {
	w := float64(f.Severity.Penalty()) / topHalves
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
	b := scoreOnce(findings, states)

	// And again, over the same findings with everything Hostveil offers a
	// button for marked fixed. See ScoreBreakdown.AfterFixes.
	//
	// Two calls: the loop below already
	// skips a Fixed finding, so "what this would be after the fixes" is the
	// same arithmetic on a different input, and there is no way for the two
	// numbers to drift apart into two answers about one host.
	offered := withOfferedFixesApplied(findings)
	after := scoreOnce(offered, states)
	safe := scoreOnce(withSafeFixesApplied(findings), states)
	b.AfterFixes = after.Overall
	b.AfterSafeFixes = safe.Overall
	for i := range b.Axes {
		b.Axes[i].AfterFixes = after.Axes[i].Score
		b.Axes[i].AfterSafeFixes = safe.Axes[i].Score
	}
	if b.Applicable {
		b.Left = pointsLeft(findings, offered, states, b.Overall, after.Overall)
		b.Left.Review = gain(after.Overall, safe.Overall)
		for _, f := range findings {
			if f.Active() && f.Remediation == RemediationReview {
				b.Left.ReviewCount++
			}
		}
	}
	return b
}

// withSafeFixesApplied is withOfferedFixesApplied for the Auto fixes alone.
func withSafeFixesApplied(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if out[i].Remediation == RemediationAuto {
			out[i].Fixed = true
			out[i].Pending = false
		}
	}
	return resolveConsequences(out)
}

// resolveConsequences marks fixed every finding whose ResolvedBy findings are
// all fixed in findings, so a projection counts what those fixes remove
// along with them.
func resolveConsequences(findings []Finding) []Finding {
	fixed := make(map[string]bool, len(findings))
	for _, f := range findings {
		if !f.Active() {
			fixed[f.Key()] = true
		}
	}
	for i := range findings {
		f := &findings[i]
		if !f.Active() || len(f.ResolvedBy) == 0 {
			continue
		}
		all := true
		for _, k := range f.ResolvedBy {
			all = all && fixed[k]
		}
		if all {
			f.Fixed, f.Pending = true, false
		}
	}
	return findings
}

// pointsLeft fills PointsLeft. Each part is the same scorer run on the
// findings with one more group treated as resolved, so the parts use the
// arithmetic the score itself uses.
func pointsLeft(findings, offered []Finding, states map[Source]ScanState, score, afterFixes uint8) PointsLeft {
	var left PointsLeft

	inForce := make([]Finding, len(findings))
	copy(inForce, findings)
	for i := range inForce {
		if inForce[i].Fixed && inForce[i].Pending {
			inForce[i].Pending = false
			left.PendingCount++
		}
	}
	if left.PendingCount > 0 {
		left.Pending = gain(scoreOnce(inForce, states).Overall, score)
	}

	resolved := make([]Finding, len(offered))
	copy(resolved, offered)
	for i := range resolved {
		f := &resolved[i]
		if !f.Active() {
			continue
		}
		switch f.Remediation {
		case RemediationManual, RemediationUnset:
			f.Fixed = true
			left.ManualCount++
		case RemediationUnavailable:
			left.UnavailableCount++
		}
	}
	withManual := scoreOnce(resolved, states).Overall
	left.Manual = gain(withManual, afterFixes)
	if left.UnavailableCount > 0 {
		left.Unavailable = gain(100, withManual)
	}
	return left
}

func gain(to, from uint8) uint8 {
	if to <= from {
		return 0
	}
	return to - from
}

// withOfferedFixesApplied returns findings with every one Hostveil can
// remediate marked Fixed.
//
// Review counts as well as Auto. The operator who wants to know what fixing
// everything gets them is going to accept the Review fixes too, that is the
// path scripts/measure/run.sh calls `reviewed`, and it exists
// because measuring only the unattended half measures half the tool.
//
// Remediation is read here, and that
// is only correct because Engine.classify runs before scoring
// (internal/core/engine.go), so the value on the finding is already resolved
// between the checker and the registry, which is to say it is exactly what
// decides whether a UI draws a button.
func withOfferedFixesApplied(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if out[i].Remediation == RemediationAuto || out[i].Remediation == RemediationReview {
			out[i].Fixed = true
			// And in force. This pass answers "where does the number land once
			// the fixes have done their work", so a fix already applied and
			// waiting on a restart has to count as done here: otherwise the
			// headroom disappears on exactly the domains it is most needed for,
			// which are the ones whose fixes are never immediate.
			out[i].Pending = false
		}
	}
	return resolveConsequences(out)
}

func scoreOnce(findings []Finding, states map[Source]ScanState) ScoreBreakdown {
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
	// multiplicatively: each one takes a share of what
	// is left, so the tenth High still hurts but cannot hurt more than there
	// is left to lose.
	//
	// Summing severities instead (the model this replaces) meant two
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
		// Active, not !Fixed: a fix whose artifact is written and not yet in
		// force has changed nothing an attacker can see, and the score is the
		// one place that must not say otherwise. See Finding.Pending.
		if !f.Active() {
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
		// One ID can carry two severities (a CVE roll-up is the worst level
		// in that image, which differs per image) and without this the same
		// two findings scored differently depending on which was seen first.
		sort.SliceStable(fs, func(i, j int) bool { return weight(fs[i], 1) > weight(fs[j], 1) })
		for n, f := range fs {
			remaining[g.axis] *= 1 - weight(f, n+1)
		}
	}

	logSum := 0.0
	ranCapSum := 0
	for i := range axes {
		lost := 1 - remaining[i]
		// Score comes from the fraction directly. Deriving it from penalty/cap would give a cap-6 axis
		// only seven distinct scores.
		axes[i].Score = uint8(math.Round(100 * remaining[i])) // remaining is 0-1
		axes[i].Penalty = int(math.Round(float64(axes[i].MaxPenalty) * lost))
		if axes[i].Applicable {
			// remaining is a product of factors of at least 0.5 each, so it
			// is never 0 and the logarithm is finite.
			logSum += float64(axes[i].MaxPenalty) * math.Log(remaining[i])
			ranCapSum += axes[i].MaxPenalty
		}
	}

	return ScoreBreakdown{
		Overall:    weightedGeometricMean(logSum, ranCapSum),
		Axes:       axes,
		Applicable: ranCapSum > 0,
	}
}

// weightedGeometricMean combines the axes that ran into the overall score:
// 100 × Π r_i^(c_i / Σc), where r_i is an axis's remaining fraction (its
// score / 100) and c_i its cap, over the axes that ran.
//
// Each r_i is already a probability-shaped quantity: the findings on an axis
// erode it multiplicatively, one High halving it. Reading r_i as the chance
// that the axis holds, the chance that every axis holds is their product, and
// an attacker needs one axis that does not. The cap is how much of the host
// an axis stands for, so it is the exponent, and dividing by Σc keeps a host
// with every axis at r scoring 100·r whichever domains ran (the
// renormalization the arithmetic mean had, kept).
//
// It replaced the cap-weighted arithmetic mean, 100 − 100·Σ c_i(1 − r_i) / Σc.
// That mean let clean domains average away a broken one: an exposed database
// and an open AI agent gateway (two axes near 0) on an otherwise tidy host read
// as 60 or more, a pass, while the host was one connection from compromise.
// The geometric mean keeps the same scale and the same extremes (every axis at
// 1 is 100, one axis at 0 drags the whole toward 0) and weighs a collapsed axis
// as the weakest link it is. One Low on a cap-5 axis among 85 still rounds to
// 100.
func weightedGeometricMean(logSum float64, ranCapSum int) uint8 {
	if ranCapSum <= 0 {
		// Callers must check ScoreBreakdown.Applicable; the value is arbitrary because there is nothing to average.
		return 0
	}
	v := math.Round(100 * math.Exp(logSum/float64(ranCapSum)))
	return uint8(max(0, min(100, v))) // bounded 0-100
}
