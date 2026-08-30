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
	"time"

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

	// Benefit is one sentence stating what applying this action actually
	// gets the operator, shown in preview beside Warning so the payoff and
	// the risk are read together — a medicine label states efficacy next
	// to side effects, not side effects alone. Required on every action
	// (see Validate), unlike Warning, which stays optional: not every fix
	// has a real side effect, but every registered fix is worth doing, so
	// it should be able to say why.
	Benefit string
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

	// NoFollow refuses to read the target through a symlink.
	//
	// It exists for the edits whose path is inside a user's home, where the
	// account being audited controls every component of it while hostveil
	// runs as root. Without it, replacing ~/.openclaw/openclaw.json with a
	// link to a root-only file between the scan and the fix would have root
	// read that file and render it into a preview diff for anyone at the
	// dashboard. The write side is already safe — WriteFileAtomic renames
	// over the link rather than through it — so the read is the whole
	// exposure, and refusing it is the discipline the mode fixes in
	// register.go committed every later home-directory fix to.
	//
	// Opt-in, because a symlinked target is legitimate elsewhere and a
	// blanket refusal would break the fix that depends on one: Ubuntu ships
	// /etc/sysctl.d/99-sysctl.conf as a link to /etc/sysctl.conf, which is
	// exactly the file persistSysctl resolves to and edits on purpose.
	NoFollow bool
	// SafeRoot is the trusted directory under which Path or Paths must live.
	// Every component below it is opened descriptor-relatively without
	// following symlinks. It supersedes NoFollow for user-controlled trees.
	SafeRoot string

	// TakesEffectOn names what has to happen before this edit reaches the
	// host — "recreated with `docker compose up -d`", "a docker daemon
	// restart". Empty means the edit is in force the moment it is written.
	//
	// It exists because the re-check cannot tell the difference on its own,
	// and got it wrong in the dangerous direction. The compose checker reads
	// the project file, the compose fix edits that file, so the re-check
	// finds nothing and reports VerifyGone — "the finding is gone" — while
	// the container that is actually running still publishes the port on
	// every interface. A positive confirmation over an unchanged host is the
	// worst single thing this tool can say.
	//
	// Where it is set, a re-check that no longer sees the finding reports
	// VerifyPending instead, because reading the artifact the fix just wrote
	// establishes that the artifact is correct and nothing more.
	//
	// This is also the whole of the objection register.go raises against the
	// dockerd and systemd domains — "a fix would edit a file the running
	// daemon will not read again until it restarts" — stated as a field
	// rather than as a reason to have no fix at all.
	TakesEffectOn string

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
	// see Engine.runEditValidator. That is what keeps a validator which cannot run
	// on this host — `sshd -t` needs host keys it may not be able to read —
	// from blocking a perfectly good fix. "Cannot verify" is not "invalid".
	VerifyCmd []string

	// Exec: one or more commands (argv, no shell) run in order as a single
	// atomic action — e.g. "allow SSH" then "enable firewall".
	Commands [][]string
	// Timeout overrides the runner's short interactive-command deadline for
	// operations such as package upgrades that legitimately take minutes.
	// Zero keeps the platform default.
	Timeout time.Duration

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
//
// # Actions[0] is the recommendation
//
// The order is not incidental. Every interface lists the alternatives in it,
// the TUI and the dashboard both preselect the first, and — the part that
// makes it load-bearing — `fix --all --review` applies index 0 without asking.
// So Actions[0] is what hostveil recommends, and it is what an operator who
// does not read them gets.
//
// That was written down in three prose comments and enforced by nothing, and
// one builder disagreed with it: ds010's memory limits led with 512m, the
// smallest, while the warning printed beside every one of them said "start
// generous… and tighten later". A reviewed batch therefore capped every
// unlimited container on the host at 512m — a media transcoder or a JVM is
// OOM-killed by that, which is the outcome the warning exists to prevent.
//
// Recommended means recommended *for unattended application*, which is not
// always what a person would pick first. The sysctl fixes are the case:
// register.go argues at length that persisting to a drop-in and applying to
// the running kernel are a genuine choice with neither dominating. For a
// batch there is no choice — the file-backed one leaves a checkpoint and
// survives a reboot — so that is index 0, and the exec alternative sits
// behind it for the human who wants the other thing.
//
// TestTheFirstAlternativeIsTheRecommendedOne pins every Review fix's index 0.
type Fix struct {
	FindingID string
	Label     string
	Kind      model.RemediationKind
	Actions   []Action
}

// EffectiveKind is Kind with the exec floor applied: an Auto fix that runs
// a command is Review, whatever it declared.
//
// "Auto means safe to apply unattended" rests on the fix being reversible,
// and an exec action writes no checkpoint — there is nothing file-backed to
// restore. So `fix --all` applying one means a command run as root, on the
// operator's host, with no way to undo it through hostveil.
//
// register.go states the rule five times over while deciding what to
// register ("`apt upgrade` is exec, so never Auto"; "Being exec, it is
// Review and can never be Auto"), and it was once upheld entirely by each
// checker choosing Review by hand. The updates domain is where that is
// visible: its fix for updates.disabled is shaped Auto — one action, which
// is all the shape rule means — and the only thing between `fix --all` and
// `apt-get install` was the checker independently declaring Review.
//
// One checker declaring Auto for a finding whose fix happens to be exec is
// all it would take, and nothing would report it. Review rather than Manual:
// the fix is still correct and still worth offering, it just needs a human to
// say go.
//
// It lives here rather than in the engine because it is a statement about
// the fix's shape and nothing else, which is what lets the docs tests ask
// the registry what a user will actually be shown.
func (f Fix) EffectiveKind() model.RemediationKind {
	if f.Kind != model.RemediationAuto {
		return f.Kind
	}
	for _, a := range f.Actions {
		if a.Kind == ActionExec {
			return model.RemediationReview
		}
	}
	return f.Kind
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
//
// It also requires Benefit on every action, unconditionally — unlike
// Warning, which stays optional because not every fix has a real side
// effect. Every fix is registered because it is worth doing, so it should
// be able to say why; a registration that cannot is the same shape defect
// this function already exists to catch before it reaches a UI as a
// silent button.
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
		if a.Benefit == "" {
			return fmt.Errorf("fix %q action %d has no Benefit", fx.FindingID, i)
		}
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
