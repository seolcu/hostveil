// Package fix maps findings to concrete remediations. A Fix is a set of
// Actions; edit actions expose a PURE Transform (bytes in, bytes out, no
// disk writes) used identically for preview (diff only) and apply (write).
// That purity is what removes v2's hazard of mutating a live file just to
// compute a preview.
package fix

import (
	"fmt"
	"io/fs"
	"path"

	"github.com/seolcu/hostveil/internal/model"
)

// ActionKind distinguishes a file edit from a shell command.
type ActionKind int

const (
	ActionEdit ActionKind = iota // mutate a file via Transform
	ActionExec                   // run a command
	ActionMode                   // change permission bits via Mode
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

	// CreateIfMissing lets an edit action target a file that does not exist
	// yet: Transform is handed nil rather than the read failing, and the
	// checkpoint records that undoing the fix means deleting the file.
	//
	// Without it an edit action could only ever modify something already on
	// disk, which left an entire detection domain unfixable. Persisting a
	// kernel parameter means writing a drop-in under /etc/sysctl.d that by
	// definition is not there — if it were, the value would already be set
	// and the finding would not have fired.
	//
	// It is opt-in per action, not the default, because for every other fix
	// a missing target is a real error worth reporting: an sshd_config that
	// is not there means the finding was stale or the path was wrong, and
	// silently creating one would be worse than failing.
	CreateIfMissing bool

	// VerifyCmd is an optional argv that validates an edit action's *result*
	// before it is written. Exactly one element must be VerifyPathToken; the
	// engine substitutes a temporary file holding the bytes Transform
	// produced. Like Commands it is argv, never a shell string.
	//
	// It exists because "the file was written" and "the service can use it"
	// are different claims, and only the second is worth marking a finding
	// fixed for. An invalid sshd_config is the case that matters: sshd keeps
	// serving from the config it already loaded, so a broken file looks like
	// nothing at all until the next restart — at which point sshd refuses to
	// start and repairing it needs the SSH access it just removed.
	//
	// The check is calibrated against the original file before it is trusted:
	// see Engine.verifyEdit. That is what keeps a validator which cannot run
	// on this host — `sshd -t` needs host keys it may not be able to read —
	// from blocking a perfectly good fix. "Cannot verify" is not "invalid".
	VerifyCmd []string

	// Exec: one or more commands (argv, no shell) run in order as a single
	// atomic action — e.g. "allow SSH" then "enable firewall".
	Commands [][]string

	// Mode: the files whose permission bits change, and a PURE function from
	// a file's current mode to its desired one. Same contract as Transform —
	// preview and apply share it, and preview never touches disk.
	//
	// Paths is a slice because one finding can cover several files (the
	// fileperms host-key rule is a glob), and an Auto fix is allowed exactly
	// one action.
	Paths []string
	Mode  func(current fs.FileMode) fs.FileMode
}

// VerifyPathToken is the placeholder an Action's VerifyCmd uses for the file
// under test. The engine replaces it with a temporary path; the live file is
// never named, which is what lets the check run before anything is written.
const VerifyPathToken = "{}"

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
// action has a Transform.
//
// core.Engine.buildFix runs it on every fix it resolves, so a registration
// whose shape contradicts its kind demotes the finding to Manual instead of
// reaching a UI as a button. It used to run only in this package's tests,
// against the representative findings those tests happen to construct,
// which left the contract unenforced for every other finding — and the
// first thing to notice a missing Transform was applyEdit calling it.
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
		if a.Kind == ActionMode {
			if len(a.Paths) == 0 {
				return fmt.Errorf("fix %q action %d is a mode change with no paths", fx.FindingID, i)
			}
			if a.Mode == nil {
				return fmt.Errorf("fix %q action %d is a mode change with no Mode function", fx.FindingID, i)
			}
		}
	}
	return nil
}
