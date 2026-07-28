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

// Rule audits one kernel parameter (or a small set that shares one
// remediation). Flagged decides from the values that exist on this kernel;
// a key whose /proc/sys file is absent simply is not in the map — the knob
// does not exist on this kernel, so there is nothing to harden.
type Rule struct {
	ID      string
	Title   string
	Sev     model.Severity
	Desc    string
	Keys    []string // dotted sysctl names, e.g. "kernel.kptr_restrict"
	Want    string   // the sysctl.d line(s) the how-to-fix recommends
	Flagged func(vals map[string]int64) bool

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
}

// New returns a sysctl checker with the default rule set.
func New() *Checker { return &Checker{Root: "/proc/sys", Rules: defaultRules()} }

func defaultRules() []Rule {
	return []Rule{
		{
			ID: "sysctl.ptrace-scope", Title: "Any process can debug its siblings",
			Sev:  model.SeverityMedium,
			Desc: "kernel.yama.ptrace_scope is 0, so every process can attach a debugger to any other process of the same user and read its memory — including the session tokens inside a running agent, browser, or password manager. Setting it to 1 limits attaching to direct children.",
			Keys: []string{"kernel.yama.ptrace_scope"},
			Want: "kernel.yama.ptrace_scope = 1",
			Set:  []string{"kernel.yama.ptrace_scope=1"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["kernel.yama.ptrace_scope"]
				return ok && val == 0
			},
		},
		{
			ID: "sysctl.syncookies", Title: "TCP SYN-flood protection is off",
			Sev:  model.SeverityMedium,
			Desc: "net.ipv4.tcp_syncookies lets listening services survive a SYN-flood denial of service. It costs nothing in normal operation and only activates under attack, which is why every mainstream distribution ships it on.",
			Keys: []string{"net.ipv4.tcp_syncookies"},
			Want: "net.ipv4.tcp_syncookies = 1",
			Set:  []string{"net.ipv4.tcp_syncookies=1"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["net.ipv4.tcp_syncookies"]
				return ok && val != 1
			},
		},
		{
			ID: "sysctl.accept-redirects", Title: "ICMP redirects are accepted",
			Sev:  model.SeverityMedium,
			Desc: "Accepting ICMP redirect messages lets a machine on the same network rewrite this host's routing decisions — a classic man-in-the-middle primitive. A server has no use for them.",
			Keys: []string{"net.ipv4.conf.all.accept_redirects"},
			Want: "net.ipv4.conf.all.accept_redirects = 0",
			Set:  []string{"net.ipv4.conf.all.accept_redirects=0"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["net.ipv4.conf.all.accept_redirects"]
				return ok && val != 0
			},
		},
		{
			ID: "sysctl.protected-links", Title: "Symlink and hardlink protections are disabled",
			Sev:  model.SeverityMedium,
			Desc: "fs.protected_symlinks and fs.protected_hardlinks close a family of /tmp link races that local attackers use to trick privileged processes into overwriting files of the attacker's choosing. Every mainstream distribution ships both enabled.",
			Keys: []string{"fs.protected_symlinks", "fs.protected_hardlinks"},
			Want: "fs.protected_symlinks = 1 and fs.protected_hardlinks = 1",
			Set:  []string{"fs.protected_symlinks=1", "fs.protected_hardlinks=1"},
			Flagged: func(v map[string]int64) bool {
				for _, k := range []string{"fs.protected_symlinks", "fs.protected_hardlinks"} {
					if val, ok := v[k]; ok && val == 0 {
						return true
					}
				}
				return false
			},
		},
		{
			ID: "sysctl.kptr-restrict", Title: "Kernel pointer addresses are visible to all users",
			Sev:  model.SeverityLow,
			Desc: "With kernel.kptr_restrict at 0, /proc exposes raw kernel pointers to any local user. Those addresses defeat kernel address-space randomization, handing a local exploit the memory layout it needs.",
			Keys: []string{"kernel.kptr_restrict"},
			Want: "kernel.kptr_restrict = 1",
			Set:  []string{"kernel.kptr_restrict=1"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["kernel.kptr_restrict"]
				return ok && val < 1
			},
		},
		{
			ID: "sysctl.dmesg-restrict", Title: "Any user can read the kernel log",
			Sev:  model.SeverityLow,
			Desc: "The kernel log leaks addresses, hardware details, and stack traces that make local privilege-escalation exploits easier to build. With kernel.dmesg_restrict at 0, every account can read it.",
			Keys: []string{"kernel.dmesg_restrict"},
			Want: "kernel.dmesg_restrict = 1",
			Set:  []string{"kernel.dmesg_restrict=1"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["kernel.dmesg_restrict"]
				return ok && val != 1
			},
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
			Flagged: func(v map[string]int64) bool {
				val, ok := v["kernel.sysrq"]
				return ok && val == 1
			},
		},
		{
			ID: "sysctl.rp-filter", Title: "Source-address spoofing filter is off",
			Sev:  model.SeverityLow,
			Desc: "Reverse-path filtering drops packets whose source address could not be reached back through the interface they arrived on — cheap protection against spoofed traffic. Strict (1) and loose (2) both count; loose is the right setting for VPN and multi-homed hosts.",
			Keys: []string{"net.ipv4.conf.all.rp_filter"},
			Want: "net.ipv4.conf.all.rp_filter = 1 (or 2 on VPN/multi-homed hosts)",
			Set:  []string{"net.ipv4.conf.all.rp_filter=1"},
			Flagged: func(v map[string]int64) bool {
				val, ok := v["net.ipv4.conf.all.rp_filter"]
				return ok && val == 0
			},
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
	var findings []model.Finding
	var unreadable []string
	covered := 0
	for _, r := range c.Rules {
		vals := map[string]int64{}
		failed := false
		for _, key := range r.Keys {
			v, err := c.readKey(key)
			switch {
			case err == nil:
				vals[key] = v
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
		findings = append(findings, model.NewFinding(r.ID, r.Title, r.Sev,
			model.SourceSysctl, model.RemediationReview,
			model.WithDescription(r.Desc),
			model.WithHowToFix(fmt.Sprintf("Add `%s` to a file under /etc/sysctl.d (e.g. 99-hardening.conf), then run `sysctl --system` to apply it without a reboot.", r.Want)),
			model.WithEvidence("value", evidenceFor(r.Keys, vals)),
			// The machine-readable form of the same recommendation, so the
			// fix registry can build an action from the finding alone — a
			// fix never sees the Rule it came from.
			model.WithEvidence("set", strings.Join(r.Set, ",")),
		))
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
func evidenceFor(keys []string, vals map[string]int64) string {
	var parts []string
	for _, k := range keys {
		if v, ok := vals[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%d", k, v))
		}
	}
	return strings.Join(parts, model.EvidenceSeparator)
}
