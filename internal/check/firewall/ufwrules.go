package firewall

import (
	"context"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// UFWView is what `ufw status verbose` says about inbound TCP, read the way
// ufw applies it: the first rule that matches a port decides it, and the
// default incoming policy decides a port no rule names.
type UFWView struct {
	// Active is false when ufw is not installed, not running, or its status
	// could not be read — in every one of those cases nothing here can say a
	// port is blocked.
	Active bool
	// HasRules reports whether any rule is listed. `ufw prepend` needs one
	// to prepend to; on an empty ruleset the fix uses a plain `ufw deny`.
	HasRules bool

	defaultDeny bool
	rules       []ufwRule
}

type ufwRule struct {
	v6     bool
	ports  func(int) bool
	action string // "allow", "limit", "deny", "reject"
}

// ReadUFW asks ufw for its rules. It runs the same `ufw status verbose` the
// firewall domain runs for the default policy, so under the scan cache the
// two cost one command.
func ReadUFW(ctx context.Context, r platform.CommandRunner) UFWView {
	if !platform.Has(r, "ufw") {
		return UFWView{}
	}
	out, err := r.Run(ctx, "ufw", "status", "verbose")
	if err != nil {
		return UFWView{}
	}
	return parseUFWStatus(string(out))
}

// Blocks reports whether inbound TCP to port is refused for both address
// families. Any allow that comes first — from anywhere or from one subnet —
// means somebody can reach it, so the answer is no.
func (v UFWView) Blocks(port int) bool {
	if !v.Active {
		return false
	}
	return v.blocks(port, false) && v.blocks(port, true)
}

func (v UFWView) blocks(port int, v6 bool) bool {
	for _, r := range v.rules {
		if r.v6 != v6 || !r.ports(port) {
			continue
		}
		return r.action == "deny" || r.action == "reject"
	}
	return v.defaultDeny
}

func parseUFWStatus(out string) UFWView {
	var v UFWView
	lower := strings.ToLower(out)
	if !strings.Contains(lower, "status: active") {
		return v
	}
	v.Active = true
	v.defaultDeny = parseUFWDefault(out) == policyDeny

	inRules := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			inRules = true
			continue
		}
		if !inRules || trimmed == "" {
			continue
		}
		cols := splitColumns(trimmed)
		if len(cols) < 3 {
			continue
		}
		to, action := cols[0], strings.ToLower(cols[1])
		verb, dir, _ := strings.Cut(action, " ")
		if dir != "" && dir != "in" {
			continue // FWD and OUT rules do not decide inbound traffic
		}
		v.HasRules = true
		v6 := strings.Contains(to, "(v6)") || strings.Contains(cols[2], "(v6)")
		match, ok := portMatcher(strings.TrimSpace(strings.Replace(to, "(v6)", "", 1)))
		if !ok {
			continue
		}
		v.rules = append(v.rules, ufwRule{v6: v6, ports: match, action: verb})
	}
	return v
}

// splitColumns splits ufw's table on runs of two or more spaces, which is
// how it separates To, Action and From while keeping "ALLOW IN" whole.
func splitColumns(s string) []string {
	var out []string
	for _, f := range strings.Split(s, "  ") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// portMatcher reads the port part of a To column: "Anywhere", "6379",
// "6379/tcp", "80,443/tcp", "6000:6007/tcp". A rule bound to an address or an
// interface, or for UDP only, is not one this reads; it is skipped rather than
// guessed at, which can only make a port look less blocked than it is.
func portMatcher(to string) (func(int) bool, bool) {
	if strings.EqualFold(to, "anywhere") {
		return func(int) bool { return true }, true
	}
	spec, proto, _ := strings.Cut(to, "/")
	if proto != "" && proto != "tcp" {
		return nil, false
	}
	if strings.ContainsAny(spec, " .") {
		return nil, false
	}
	var ranges [][2]int
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, false
			}
		}
		ranges = append(ranges, [2]int{a, b})
	}
	return func(p int) bool {
		for _, r := range ranges {
			if p >= r[0] && p <= r[1] {
				return true
			}
		}
		return false
	}, true
}
