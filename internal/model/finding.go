package model

import "fmt"

// Finding is a single security or hardening issue detected by one of the
// checkers. Construct findings with NewFinding so the required fields
// (id, title, severity, source, remediation) can never be left at an
// unsafe zero value.
type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	HowToFix    string            `json:"how_to_fix"`
	Severity    Severity          `json:"severity"`
	Source      Source            `json:"source"`
	Service     string            `json:"service"`
	Remediation RemediationKind   `json:"remediation"`
	Evidence    map[string]string `json:"evidence,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Fixed       bool              `json:"fixed"`

	// Pending means hostveil applied a fix for this finding and the host has
	// not changed yet: the artifact on disk is correct and whatever reads it
	// has not read it again.
	//
	// It exists because "hostveil wrote the file" and "the risk is gone" are
	// different claims, and the score was crediting the first. Applying a
	// compose fix marked the finding Fixed and moved the number while the
	// container still ran the old configuration — the same mismatch
	// Action.TakesEffectOn and VerifyPending were added to *describe*, arriving
	// in the one place that is supposed to be measuring the host rather than
	// hostveil's own activity.
	//
	// Ask Active, not this field, for whether a risk is still standing; Fixed
	// keeps its own meaning of "hostveil applied a fix here" and is what the
	// apply paths test so a pending fix is never applied twice.
	//
	// Never trust it from a snapshot. It describes an apply that happened in
	// this process, and the next scan re-derives everything from the checkers.
	Pending bool `json:"pending,omitempty"`

	// WhyNoFix is one sentence saying what stops hostveil fixing this
	// finding for you. It is set by the engine, never by a checker, and only
	// on findings that reach a UI with no fix to offer.
	//
	// "Manual" is a decision — someone weighed the remediation and refused it
	// — but in an interface it is indistinguishable from a finding nobody has
	// looked at. The reasons have been written down since the beginning, in
	// the doc comment on fix.Default(), where a user never sees them; this is
	// that register reaching the finding it is about.
	WhyNoFix string `json:"why_no_fix,omitempty"`
}

// FindingOption customizes optional fields of a Finding.
type FindingOption func(*Finding)

// WithDescription sets the plain-language description of the problem.
func WithDescription(s string) FindingOption { return func(f *Finding) { f.Description = s } }

// WithHowToFix sets the deterministic, always-available fix guidance.
func WithHowToFix(s string) FindingOption { return func(f *Finding) { f.HowToFix = s } }

// WithService attributes the finding to a specific service (e.g. a
// compose service name); empty means host-level.
func WithService(s string) FindingOption { return func(f *Finding) { f.Service = s } }

// WithEvidence attaches a single key/value piece of evidence. It is
// additive across calls.
func WithEvidence(key, val string) FindingOption {
	return func(f *Finding) {
		if f.Evidence == nil {
			f.Evidence = map[string]string{}
		}
		f.Evidence[key] = val
	}
}

// WithMetadata attaches a single key/value metadata entry (used by fixes
// to locate the artifact). It is additive across calls.
func WithMetadata(key, val string) FindingOption {
	return func(f *Finding) {
		if f.Metadata == nil {
			f.Metadata = map[string]string{}
		}
		f.Metadata[key] = val
	}
}

// NewFinding builds a Finding with all required fields set explicitly.
// The required arguments make the v2 zero-value footguns unrepresentable:
// there is no way to get a finding without a real severity, source, and
// remediation kind.
func NewFinding(id, title string, sev Severity, src Source, rem RemediationKind, opts ...FindingOption) Finding {
	f := Finding{
		ID:          id,
		Title:       title,
		Severity:    sev,
		Source:      src,
		Remediation: rem,
	}
	for _, opt := range opts {
		opt(&f)
	}
	return f
}

// Validate reports why a finding is malformed, or nil if it is well
// formed. The engine runs this over every finding after a scan so an
// unclassified or unsourced finding can never reach a UI.
func (f Finding) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("finding has empty ID")
	}
	if f.Title == "" {
		return fmt.Errorf("finding %q has empty title", f.ID)
	}
	if !f.Source.Valid() {
		return fmt.Errorf("finding %q has unset source", f.ID)
	}
	if !f.Remediation.Valid() {
		return fmt.Errorf("finding %q has unset remediation", f.ID)
	}
	return nil
}

// IsFixable reports whether hostveil can offer an automated fix.
func (f Finding) IsFixable() bool {
	return f.Remediation.IsFixable()
}

// IsAutoFixable reports whether "fix all safe" would apply this row right
// now. It is IsFixable's narrower cousin: that one asks what kind of
// remediation exists, this one asks whether the batch is going to act.
//
// The !Fixed half is what stops a pending row being offered. Its fix has been
// applied and what is outstanding is a restart, so the batch skips it — and a
// UI that let the operator mark it anyway would put it in a batch that
// reported it back under "skipped", the same word that means "there is no fix
// for this one".
func (f Finding) IsAutoFixable() bool {
	return !f.Fixed && f.Remediation == RemediationAuto
}

// Active reports whether this risk is still standing on the host — either
// nothing has been applied, or something has and it is not in force yet.
//
// It is the question the score, the SARIF results, the exit status, the delta
// and every visible list are asking, and it is deliberately one named
// predicate rather than "!f.Fixed || f.Pending" written out at each of them.
// A rule that lives in prose until one renderer forgets it is the drift
// internal/docs/afterfixes_test.go exists to catch, and there is no reason to
// hand it a fresh instance.
//
// The other question — has hostveil already applied a fix here — is Fixed on
// its own, and the two diverge exactly on a pending fix: it stays charged and
// visible, and it is not applied again.
func (f Finding) Active() bool { return !f.Fixed || f.Pending }

// Key uniquely identifies a finding within a report for deduplication
// and cascade matching: (source, id, service).
func (f Finding) Key() string {
	return f.Source.String() + "|" + f.ID + "|" + f.Service
}
