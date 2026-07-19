// Package fix maps findings to concrete remediations. A Fix is a set of
// Actions; edit actions expose a PURE Transform (bytes in, bytes out, no
// disk writes) used identically for preview (diff only) and apply (write).
// That purity is what removes v2's hazard of mutating a live file just to
// compute a preview.
package fix

import (
	"fmt"
	"path"

	"github.com/seolcu/hostveil/internal/model"
)

// ActionKind distinguishes a file edit from a shell command.
type ActionKind int

const (
	ActionEdit ActionKind = iota // mutate a file via Transform
	ActionExec                   // run a command
)

// Action is one step of a fix. For ActionEdit, Path + Transform are set
// and Transform is pure. For ActionExec, Command is set.
type Action struct {
	Label   string
	Warning string // shown in preview for risky actions (e.g. may lock out SSH)
	Kind    ActionKind

	// Edit
	Path      string
	Transform func(in []byte) (out []byte, err error)

	// Exec: one or more commands (argv, no shell) run in order as a single
	// atomic action — e.g. "allow SSH" then "enable firewall".
	Commands [][]string
}

// Fix is the remediation for one finding: a label, an explicit
// remediation kind, and one or more actions. For Review fixes the actions
// are independent ALTERNATIVES (the user picks one), never sequential
// steps.
type Fix struct {
	FindingID string
	Label     string
	Kind      model.RemediationKind
	Actions   []Action
}

// Builder produces a concrete Fix for a specific finding, reading its
// service, evidence, and metadata to target the right artifact.
type Builder func(f model.Finding) (Fix, error)

type registration struct {
	pattern string
	build   Builder
}

// Registry resolves a finding to its Fix. Patterns may be exact finding
// IDs or globs (e.g. "cve.*").
type Registry struct {
	regs []registration
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register associates a finding-ID pattern with a Fix builder.
func (r *Registry) Register(pattern string, b Builder) {
	r.regs = append(r.regs, registration{pattern: pattern, build: b})
}

// Build returns the Fix for a finding, ok=false if none is registered.
func (r *Registry) Build(f model.Finding) (Fix, bool, error) {
	for _, reg := range r.regs {
		if matchPattern(reg.pattern, f.ID) {
			fx, err := reg.build(f)
			if err != nil {
				return Fix{}, true, err
			}
			fx.FindingID = f.ID
			return fx, true, nil
		}
	}
	return Fix{}, false, nil
}

// Patterns returns every registered pattern. Tests enumerate the registry
// through this rather than a hand-maintained list of IDs, which silently
// drifts out of date the moment a registration is added without one.
func (r *Registry) Patterns() []string {
	out := make([]string, 0, len(r.regs))
	for _, reg := range r.regs {
		out = append(out, reg.pattern)
	}
	return out
}

// Has reports whether a fix is registered for a finding ID pattern.
func (r *Registry) Has(id string) bool {
	for _, reg := range r.regs {
		if matchPattern(reg.pattern, id) {
			return true
		}
	}
	return false
}

func matchPattern(pattern, id string) bool {
	if pattern == id {
		return true
	}
	ok, err := path.Match(pattern, id)
	return err == nil && ok
}

// Validate checks a Fix's shape against its kind: Auto has exactly one
// action, Review has two or more independent alternatives, and every edit
// action has a Transform. It is used by tests and can gate registration.
func Validate(fx Fix) error {
	switch fx.Kind {
	case model.RemediationAuto:
		if len(fx.Actions) != 1 {
			return fmt.Errorf("auto fix %q must have exactly 1 action, has %d", fx.FindingID, len(fx.Actions))
		}
	case model.RemediationReview:
		if len(fx.Actions) < 2 {
			return fmt.Errorf("review fix %q must have >= 2 alternatives, has %d", fx.FindingID, len(fx.Actions))
		}
	default:
		return fmt.Errorf("fix %q has non-fixable kind %v", fx.FindingID, fx.Kind)
	}
	for i, a := range fx.Actions {
		if a.Kind == ActionEdit && a.Transform == nil {
			return fmt.Errorf("fix %q action %d is an edit with no Transform", fx.FindingID, i)
		}
		if a.Kind == ActionExec && len(a.Commands) == 0 {
			return fmt.Errorf("fix %q action %d is an exec with no command", fx.FindingID, i)
		}
	}
	return nil
}
