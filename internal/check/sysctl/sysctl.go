// Package sysctl implements a kernel-hardening checker over the runtime
// values in /proc/sys. It audits a small, defensible set of parameters
// whose safe value is the same on essentially every self-hosted server —
// the quiet knobs that stop a local foothold from becoming root and a
// spoofed packet from becoming a route.
//
// net.ipv4.ip_forward is deliberately not audited. Docker, WireGuard,
// Tailscale exit nodes, libvirt, LXD, and Kubernetes all legitimately
// enable it, none of that is detectable from here, and a rule that accuses
// most self-hosters' routers erodes trust in the whole domain.
package sysctl

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Reading is one parameter as this kernel gave it. Present is false when the
// /proc/sys file is absent — the knob is not built into this kernel, which is
// not the same as the knob being set to zero and is the distinction the whole
// domain turns on.
type Reading struct {
	Value   int64
	Present bool
}

// Rule audits one kernel parameter (or a small set that shares one
// remediation). Flagged decides from the values that exist on this kernel;
// a parameter this kernel does not have arrives Present: false, so there is
// nothing to harden.
type Rule struct {
	ID    string
	Title string
	Sev   model.Severity
	Desc  string
	Keys  []string // dotted sysctl names, e.g. "kernel.kptr_restrict"
	Want  string   // the sysctl.d line(s) the how-to-fix recommends

	// Flagged is handed the readings for Keys, in Keys order, and nothing
	// else. Use is/isNot/below/anyIs rather than writing one out.
	//
	// It used to take the whole reading as a map, and every rule spelled its
	// own key out a second time inside the closure to look it up. Two copies
	// of one string with nothing holding them together, and a divergence
	// between them fails in the worst available direction: the map is built
	// from Keys, so a closure asking for anything else gets the zero value
	// with ok=false, answers "not flagged", and the rule silently stops
	// existing on every host. Not a rule that reports the wrong thing — a
	// rule that reports nothing, which is indistinguishable from a clean
	// kernel.
	//
	// Passing the values positionally is what makes that unrepresentable:
	// there is no key to get wrong, because there is no key.
	Flagged func(vals []Reading) bool

	// Set is the same recommendation as Want in machine-readable form: the
	// exact key=value pairs a fix writes into a drop-in or passes to
	// `sysctl -w`. Want stays prose because it also carries the caveats
	// ("or 2 on VPN/multi-homed hosts") that a person needs and a fix must
	// not act on.
	//
	// It names only keys this rule actually audits. Writing a value the
	// checker never reads would produce a fix whose effect the next scan
	// cannot confirm, and on a host with IPv6 disabled `sysctl -w` on an
	// absent key fails outright — taking the rest of the fix with it.
	Set []string
}

// Checker reports weak kernel-parameter values.
type Checker struct {
	// Root is the /proc/sys mount to read; overridable for tests.
	Root string
	// Rules is the parameter set to audit; overridable for tests.
	Rules []Rule
	// ConfDirs and ConfFile are the sysctl.d search path and the legacy
	// single file, read to find out which one decides a weak value. See
	// origin.go; overridable for tests.
	ConfDirs []string
	ConfFile string
	// InContainer answers whether this scan is running inside a container.
	// Injected so the demotion below can be tested at all: the real gate
	// reads /.dockerenv and /proc/1, and a test cannot make this process be
	// in a container. nil means the real one — see New.
	InContainer func() (bool, string)
}

// New returns a sysctl checker with the default rule set.
func New() *Checker {
	return &Checker{
		Root:     "/proc/sys",
		Rules:    defaultRules(),
		ConfDirs: defaultConfDirs(),
		ConfFile: defaultConfFile,
	}
}

// containerGate is the check's own view of the question, defaulting to the
// platform one. Kept as a method so every call site reads the same whether or
// not a test replaced it.
func (c *Checker) containerGate() (bool, string) {
	if c.InContainer != nil {
		return c.InContainer()
	}
	return platform.ContainerRuntime()
}

// The predicates the rules use. A rule with one key reads as `is(0)`, and
// there is no second copy of its key to drift from Keys.
//
// Each takes the readings for the rule's own Keys. A parameter this kernel
// does not have is never a finding: an absent knob cannot be misconfigured,
// and treating Present: false as a zero would flag every kernel built without
// Yama for having ptrace_scope "set to 0".

// is flags the single key when the kernel has it and it equals n.
func is(n int64) func([]Reading) bool {
	return func(v []Reading) bool { return v[0].Present && v[0].Value == n }
}

// isNot flags the single key when the kernel has it and it is anything but n.
func isNot(n int64) func([]Reading) bool {
	return func(v []Reading) bool { return v[0].Present && v[0].Value != n }
}

// below flags the single key when the kernel has it and it is under n.
func below(n int64) func([]Reading) bool {
	return func(v []Reading) bool { return v[0].Present && v[0].Value < n }
}

// anyIs flags when any key the kernel has equals n. For the rules where two
// parameters share one remediation and either one being off is the finding.
func anyIs(n int64) func([]Reading) bool {
	return func(vals []Reading) bool {
		for _, v := range vals {
			if v.Present && v.Value == n {
				return true
			}
		}
		return false
	}
}

func defaultRules() []Rule {
	return []Rule{
		{
			ID: "sysctl.ptrace-scope", Title: "Any process can debug its siblings",
			Sev:     model.SeverityMedium,
			Desc:    "kernel.yama.ptrace_scope is 0, so every process can attach a debugger to any other process of the same user and read its memory — including the session tokens inside a running agent, browser, or password manager. Setting it to 1 limits attaching to direct children.",
			Keys:    []string{"kernel.yama.ptrace_scope"},
			Want:    "kernel.yama.ptrace_scope = 1",
			Set:     []string{"kernel.yama.ptrace_scope=1"},
			Flagged: is(0),
		},
		{
			ID: "sysctl.syncookies", Title: "TCP SYN-flood protection is off",
			Sev:     model.SeverityMedium,
			Desc:    "net.ipv4.tcp_syncookies lets listening services survive a SYN-flood denial of service. It costs nothing in normal operation and only activates under attack, which is why every mainstream distribution ships it on.",
			Keys:    []string{"net.ipv4.tcp_syncookies"},
			Want:    "net.ipv4.tcp_syncookies = 1",
			Set:     []string{"net.ipv4.tcp_syncookies=1"},
			Flagged: isNot(1),
		},
		{
			ID: "sysctl.accept-redirects", Title: "ICMP redirects are accepted",
			Sev:     model.SeverityMedium,
			Desc:    "Accepting ICMP redirect messages lets a machine on the same network rewrite this host's routing decisions — a classic man-in-the-middle primitive. A server has no use for them.",
			Keys:    []string{"net.ipv4.conf.all.accept_redirects"},
			Want:    "net.ipv4.conf.all.accept_redirects = 0",
			Set:     []string{"net.ipv4.conf.all.accept_redirects=0"},
			Flagged: isNot(0),
		},
		{
			ID: "sysctl.protected-links", Title: "Symlink and hardlink protections are disabled",
			Sev:     model.SeverityMedium,
			Desc:    "fs.protected_symlinks and fs.protected_hardlinks close a family of /tmp link races that local attackers use to trick privileged processes into overwriting files of the attacker's choosing. Every mainstream distribution ships both enabled.",
			Keys:    []string{"fs.protected_symlinks", "fs.protected_hardlinks"},
			Want:    "fs.protected_symlinks = 1 and fs.protected_hardlinks = 1",
			Set:     []string{"fs.protected_symlinks=1", "fs.protected_hardlinks=1"},
			Flagged: anyIs(0),
		},
		{
			ID: "sysctl.kptr-restrict", Title: "Kernel pointer addresses are visible to all users",
			Sev:     model.SeverityLow,
			Desc:    "With kernel.kptr_restrict at 0, /proc exposes raw kernel pointers to any local user. Those addresses defeat kernel address-space randomization, handing a local exploit the memory layout it needs.",
			Keys:    []string{"kernel.kptr_restrict"},
			Want:    "kernel.kptr_restrict = 1",
			Set:     []string{"kernel.kptr_restrict=1"},
			Flagged: below(1),
		},
		{
			ID: "sysctl.dmesg-restrict", Title: "Any user can read the kernel log",
			Sev:     model.SeverityLow,
			Desc:    "The kernel log leaks addresses, hardware details, and stack traces that make local privilege-escalation exploits easier to build. With kernel.dmesg_restrict at 0, every account can read it.",
			Keys:    []string{"kernel.dmesg_restrict"},
			Want:    "kernel.dmesg_restrict = 1",
			Set:     []string{"kernel.dmesg_restrict=1"},
			Flagged: isNot(1),
		},
		{
			ID: "sysctl.sysrq", Title: "Magic SysRq is fully enabled",
			Sev:  model.SeverityLow,
			Desc: "kernel.sysrq = 1 enables every SysRq function, letting anyone with console, serial, or IPMI access kill processes, remount filesystems, or crash the machine with a keystroke. Distributions default to 0 or a restricted bitmask for a reason.",
			Keys: []string{"kernel.sysrq"},
			Want: "kernel.sysrq = 0 (or a restricted bitmask such as 176)",
			Set:  []string{"kernel.sysrq=0"},
			// Only the fully-enabled value is flagged: anything else is
			// either off or a deliberate restricted mask.
			Flagged: is(1),
		},
		{
			ID: "sysctl.rp-filter", Title: "Source-address spoofing filter is off",
			Sev:     model.SeverityLow,
			Desc:    "Reverse-path filtering drops packets whose source address could not be reached back through the interface they arrived on — cheap protection against spoofed traffic. Strict (1) and loose (2) both count; loose is the right setting for VPN and multi-homed hosts.",
			Keys:    []string{"net.ipv4.conf.all.rp_filter"},
			Want:    "net.ipv4.conf.all.rp_filter = 1 (or 2 on VPN/multi-homed hosts)",
			Set:     []string{"net.ipv4.conf.all.rp_filter=1"},
			Flagged: is(0),
		},
	}
}

// Source identifies the sysctl domain.
func (*Checker) Source() model.Source { return model.SourceSysctl }

// Available requires a readable /proc/sys. Its absence (non-Linux test
// environments, heavily sandboxed containers) is a clean skip: there are no
// kernel parameters to audit, not an error to report.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	fi, err := os.Stat(filepath.Join(c.Root, "kernel"))
	if err != nil || !fi.IsDir() {
		return false, "/proc/sys is not readable — kernel parameters cannot be audited"
	}
	return true, ""
}

// Check reads each rule's parameters and flags weak values. A parameter
// whose file does not exist is a knob this kernel does not have (Yama not
// built, IPv4 disabled) and is silently fine; one that exists but cannot be
// read is ground not covered, and the domain says so with a PartialError
// rather than letting "could not look" pass for "nothing there".
func (c *Checker) Check(_ context.Context, _ platform.Env) ([]model.Finding, error) {
	// Asked once for the whole scan rather than per rule: it is a question
	// about the host, and the answer cannot change between two rules.
	inContainer, containerWhy := c.containerGate()

	var findings []model.Finding
	var unreadable []string
	covered := 0
	byKey := origins(c.ConfDirs, c.ConfFile)
	for _, r := range c.Rules {
		vals := make([]Reading, len(r.Keys))
		failed := false
		for i, key := range r.Keys {
			v, err := c.readKey(key)
			switch {
			case err == nil:
				vals[i] = Reading{Value: v, Present: true}
			case os.IsNotExist(err):
				// absent knob — nothing to audit
			default:
				unreadable = append(unreadable, key)
				failed = true
			}
		}
		if failed {
			continue
		}
		covered++
		if !r.Flagged(vals) {
			continue
		}
		opts := []model.FindingOption{
			model.WithDescription(r.Desc),
			model.WithEvidence("value", evidenceFor(r.Keys, vals)),
			// The machine-readable form of the same recommendation, so the
			// fix registry can build an action from the finding alone — a
			// fix never sees the Rule it came from.
			model.WithEvidence("set", strings.Join(r.Set, ",")),
		}
		if origin, ok := originOf(r.Keys, vals, byKey); ok {
			// Name the file, and tell the operator to edit it rather than to
			// add a drop-in. A new file under /etc/sysctl.d is only read
			// before this one on the hosts where it happens to sort earlier,
			// and on the common case — Ubuntu's 99-sysctl.conf symlink to
			// /etc/sysctl.conf — it is read before it and loses silently.
			opts = append(opts,
				model.WithEvidence("set-by", origin.String()),
				model.WithHowToFix(fmt.Sprintf(
					"`%s` sets this value and is read after anything in /etc/sysctl.d, so a new drop-in there would not take effect. Change that line to `%s`, then run `sysctl --system` to apply it without a reboot.",
					origin, r.Want)))
		} else {
			opts = append(opts, model.WithHowToFix(fmt.Sprintf(
				"Add `%s` to a file under /etc/sysctl.d (e.g. 99-hardening.conf), then run `sysctl --system` to apply it without a reboot.", r.Want)))
		}
		f := model.NewFinding(r.ID, r.Title, r.Sev,
			model.SourceSysctl, model.RemediationReview, opts...)
		if inContainer {
			demoteForContainer(&f, containerWhy, r.Want)
		}
		findings = append(findings, f)
	}
	if len(unreadable) > 0 {
		return findings, &check.PartialError{
			Reason:  "cannot read " + strings.Join(unreadable, ", ") + " — those kernel parameters were not audited",
			Covered: covered,
			Total:   len(c.Rules),
		}
	}
	return findings, nil
}

// demoteForContainer turns a sysctl finding into a Manual one when the scan is
// running inside a container.
//
// The *reading* is not wrong and the finding stays: /proc/sys inside a
// container shows the host kernel's value for every knob that is not
// namespaced — kernel.kptr_restrict and kernel.dmesg_restrict among them — so
// the weakness being reported is real and it is the host's.
//
// The *fix* is the problem. It writes /etc/sysctl.d/60-hostveil-*.conf and
// declares it takes effect on `sysctl --system` or the next boot. Neither can
// reach the host kernel from in here, and the drop-in disappears with the
// container besides. So the file would appear, the fix would report success, a
// checkpoint would be recorded, and the value would never move — which
// internal/fix/sysctl.go already calls the worst available outcome, and
// declines for a drop-in that would lose to a file under /usr or /run. This is
// the same refusal, for a stronger version of the same reason.
//
// It is done here rather than in the fix registry because this is a statement
// about how much human judgement the finding needs, which is the checker's
// half of that decision. Engine.classify resolves the two by taking whichever
// is more cautious, so declaring Manual is enough on its own — the registered
// Review fix is never offered, and nothing in internal/fix has to learn what a
// container is.
//
// Reachable through instructions this project publishes: the README and the
// measured-results page both say to try it on a container, and
// `fix --all --review` applies these.
func demoteForContainer(f *model.Finding, why, want string) {
	f.Remediation = model.RemediationManual
	f.WhyNoFix = "This is a container. The value is the host kernel's, and no file written in here can change it."
	f.HowToFix = why + ", so a drop-in written in here cannot change the value — it belongs to the host kernel, " +
		"and this filesystem goes away with the container. Set `" + want + "` on the host instead, under its /etc/sysctl.d, " +
		"then run `sysctl --system` there."
	f.Evidence = mergeEvidence(f.Evidence, "scanned_from", "inside a container")
}

// mergeEvidence adds a key to a finding's evidence, which NewFinding built and
// may have left nil.
func mergeEvidence(m map[string]string, key, val string) map[string]string {
	if m == nil {
		return map[string]string{key: val}
	}
	m[key] = val
	return m
}

// readKey reads one dotted sysctl key from Root and parses its first field
// as an integer. All audited parameters are single integers; anything else
// is treated as unreadable rather than guessed at.
func (c *Checker) readKey(key string) (int64, error) {
	path := filepath.Join(c.Root, strings.ReplaceAll(key, ".", "/"))
	data, err := os.ReadFile(path) //nolint:gosec // paths are the fixed rule table under /proc/sys
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, fmt.Errorf("%s: empty value", key)
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// evidenceFor renders the observed values in rule-key order, so evidence is
// stable across scans and a repeat scan produces no delta nobody caused.
func evidenceFor(keys []string, vals []Reading) string {
	var parts []string
	for i, k := range keys {
		if vals[i].Present {
			parts = append(parts, fmt.Sprintf("%s=%d", k, vals[i].Value))
		}
	}
	return strings.Join(parts, model.EvidenceSeparator)
}
