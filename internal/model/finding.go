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

// Key uniquely identifies a finding within a report for deduplication
// and cascade matching: (source, id, service).
func (f Finding) Key() string {
	return f.Source.String() + "|" + f.ID + "|" + f.Service
}
