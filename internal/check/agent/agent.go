// Package agent implements a checker for self-hosted AI agent runtimes such
// as OpenClaw and Hermes Agent. Each runs a network gateway and keeps API
// keys on disk in a user's home; misconfigured, the failure mode is
// unauthenticated remote code execution as a real account.
//
// The scope is deliberately narrow. These projects ship their own config
// auditors, which cover their settings far more thoroughly than hostveil
// could sustain across two fast-moving upstream schemas. What they cannot see
// is the host: whether the gateway is *actually* listening on a reachable
// address, whether a firewall is standing behind it, whether the credential
// file is readable by everyone with an account. That is what this checker
// judges, plus a small set of stable, unambiguous config keys where the
// insecure value has no legitimate reading.
package agent

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/firewall"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports insecure self-hosted agent runtime deployments.
type Checker struct {
	// PasswdPath and Runtimes are overridable for tests.
	PasswdPath string
	Runtimes   []Runtime
}

// New returns an agent checker with the shipped runtime registry.
func New() *Checker {
	return &Checker{PasswdPath: "/etc/passwd", Runtimes: defaultRuntimes()}
}

// Source identifies the agent domain.
func (*Checker) Source() model.Source { return model.SourceAgent }

// Available probes for an actual agent installation, not merely for the
// ability to look.
//
// The two failure modes are kept distinct on purpose. An unreadable
// /etc/passwd means we could not look, and a host with no runtime installed
// means there was nothing to find; both skip the domain, but conflating them
// would let "I couldn't look" pass for "nothing there". The domain is skipped
// rather than reported clean because a host that has never installed an agent
// should not collect a free perfect score for a domain that never applied.
func (c *Checker) Available(_ context.Context, _ platform.Env) (bool, string) {
	hs, err := homes(c.PasswdPath)
	if err != nil {
		return false, "cannot read " + c.PasswdPath + " to locate home directories"
	}
	found, _ := installs(hs, c.Runtimes)
	if len(found) == 0 {
		names := make([]string, 0, len(c.Runtimes))
		for _, rt := range c.Runtimes {
			names = append(names, rt.Display)
		}
		return false, "no self-hosted agent runtime found (" + strings.Join(names, ", ") + ")"
	}
	return true, ""
}

// scan is one runtime installation plus whatever we managed to read of it.
type scan struct {
	in       install
	cfg      map[string]any
	cfgKnown bool
	env      envFile
	envKnown bool
}

// Check audits every discovered runtime installation.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	hs, err := homes(c.PasswdPath)
	if err != nil {
		return nil, err
	}
	found, unreadableHomes := installs(hs, c.Runtimes)

	// A missing or failing `ss` is not partial coverage: the config is the
	// authoritative statement of what the operator asked for, and the listener
	// only corroborates it and sharpens the severity. Losing a confidence
	// booster is not losing ground.
	listeners, _ := platform.Listeners(ctx, env.Runner)
	// Likewise the firewall: it decides only whether an exposed gateway is
	// High or Critical, never whether the finding exists.
	fwStatus, _ := firewall.Probe(ctx, env.Runner)

	var findings []model.Finding
	var reasons []string
	// Coverage counts configs we needed to read, not installs. An install
	// that has no config file yet is not ground we failed to cover, and
	// counting it would understate the fraction for no reason.
	covered, total := 0, 0

	for _, in := range found {
		s := scan{in: in}

		if rel := in.rt.EnvFile; rel != "" {
			safe := make([]string, 0, len(in.rt.EnvOverrides))
			for _, v := range in.rt.EnvOverrides {
				safe = append(safe, v)
			}
			if ef, err := loadEnvFile(in.path(rel), safe); err == nil {
				s.env, s.envKnown = ef, true
			}
		}

		b, err := os.ReadFile(in.path(in.rt.Config)) //nolint:gosec // path from the runtime registry
		switch {
		case err != nil && os.IsNotExist(err):
			// Installed but never configured. Nothing to read, nothing lost.
		case err != nil:
			total++
			reasons = append(reasons, fmt.Sprintf("cannot read %s config for %s", in.rt.Display, in.user.Name))
		default:
			total++
			cfg, derr := decodeConfig(b, in.rt.Format)
			if derr != nil {
				// An unparseable config is our blind spot, not the operator's
				// defect, so it degrades coverage without inventing a finding.
				reasons = append(reasons, fmt.Sprintf("cannot parse %s config for %s", in.rt.Display, in.user.Name))
			} else {
				s.cfg, s.cfgKnown = cfg, true
				covered++
			}
		}

		findings = append(findings, modeFindings(s)...)
		findings = append(findings, gatewayFindings(s, listeners, fwStatus)...)
		if s.cfgKnown {
			findings = append(findings, dangerFindings(s)...)
		}
	}

	for _, h := range unreadableHomes {
		reasons = append(reasons, "cannot read home directory "+h)
	}
	if len(reasons) > 0 {
		sort.Strings(reasons)
		return findings, &check.PartialError{
			Reason:  strings.Join(reasons, "; ") + " — re-run with sudo for full coverage",
			Covered: covered,
			Total:   total,
		}
	}
	return findings, nil
}

// modeFindings flags registry paths whose permissions are looser than the
// runtime's own hardened baseline.
func modeFindings(s scan) []model.Finding {
	var out []model.Finding
	for _, rule := range s.in.rt.Modes {
		path := s.in.path(rule.Rel)
		fi, err := os.Stat(path)
		if err != nil {
			continue // a path the user never created is not a finding
		}
		if fi.IsDir() != rule.Dir {
			continue // the layout is not what the registry describes; do not guess
		}
		perm := fi.Mode().Perm()
		if perm&^rule.Max == 0 {
			continue
		}

		var keys []string
		if rule.Secret && !rule.Dir {
			// "Secrets live in a secrets file" is the design, not a defect.
			// The finding is only meaningful once we know real credentials are
			// in there *and* the file is readable beyond its owner.
			keys = secretKeysIn(s, path)
			if len(keys) == 0 {
				continue
			}
		}

		id, title, desc := "agent.config-perms",
			s.in.rt.Display+" configuration is readable beyond its owner",
			"This file configures an agent that can run commands and hold credentials. Any account able to read it learns how the agent is set up; any account able to write it can retarget the agent."
		sev := model.SeverityMedium
		if rule.Secret {
			id, sev = "agent.secret-exposed", model.SeverityHigh
			title = s.in.rt.Display + " credentials are readable beyond their owner"
			desc = "This path holds the API keys the agent authenticates with. Every account on this host can read it, so any of them — or anything running as them — can take those keys and spend, read, or act with them elsewhere."
		}

		opts := []model.FindingOption{
			// The path is part of the subject: two rules under one install
			// are two distinct problems and must not collapse into one Key.
			model.WithService(s.in.subject() + ":" + rule.Rel),
			model.WithDescription(desc),
			model.WithHowToFix(fmt.Sprintf("Tighten it to %#o, e.g. `chmod %#o %s`. Upstream ships this path at %#o; if a service account reads it via group permissions, give that account its own copy instead of widening this one.", rule.Max, rule.Max, path, rule.Max)),
			model.WithEvidence("files", fmt.Sprintf("%s (%#o)", path, perm)),
			// The machine-readable twin of "files", in the shape the mode fix
			// expects. Parsing paths back out of the human string breaks on
			// any path containing ", " or " (".
			model.WithEvidence("paths", path),
			model.WithEvidence("expected", fmt.Sprintf("%#o", rule.Max)),
		}
		if len(keys) > 0 {
			// Names only. The values are the thing being protected, and
			// evidence is rendered by every UI and persisted to disk.
			opts = append(opts, model.WithEvidence("keys", strings.Join(keys, model.EvidenceSeparator)))
		}
		out = append(out, model.NewFinding(id, title, sev, model.SourceAgent, model.RemediationAuto, opts...))
	}
	return out
}

// secretKeysIn returns the credential-named keys carrying a literal value in
// a KEY=value file, reusing the already-parsed env file when it is the same
// path.
func secretKeysIn(s scan, path string) []string {
	if s.envKnown && s.in.rt.EnvFile != "" && path == s.in.path(s.in.rt.EnvFile) {
		return s.env.SecretKeys
	}
	ef, err := loadEnvFile(path, nil)
	if err != nil {
		return nil
	}
	return ef.SecretKeys
}

// gatewayFindings judges the runtime's network exposure from its configured
// bind, corroborated by what the host is actually listening on.
func gatewayFindings(s scan, listeners []platform.Listener, fw firewall.Status) []model.Finding {
	gw := s.in.rt.Gateway
	if gw.BindKey == "" {
		return nil
	}

	port := gw.DefaultPort
	if s.cfgKnown && gw.PortKey != "" {
		if v := lookupString(s.cfg, gw.PortKey); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
	}

	// Resolve the bind: config first, then the documented default, then any
	// environment override. An empty result means "we cannot tell", which is
	// different from "loopback" — we fall back to the listener rather than
	// assuming either way.
	bind := ""
	if s.cfgKnown {
		if bind = lookupString(s.cfg, gw.BindKey); bind == "" {
			bind = gw.BindDefault
		}
	}
	if s.envKnown {
		if ev, ok := s.in.rt.EnvOverrides[gw.BindKey]; ok {
			if v := s.env.Values[ev]; v != "" {
				bind = v
			}
		}
	}
	bindExposed := bind != "" && !slices.Contains(gw.LoopbackOnly, bind)

	listener, listenerFound := matchListener(listeners, port, gw.ProcNames)
	if !bindExposed && !listenerFound {
		return nil
	}

	basis := "config"
	switch {
	case bindExposed && listenerFound:
		basis = "config+listener"
	case listenerFound:
		basis = "listener"
	}

	// The firewall decides how bad it is, never whether it is true. An
	// observed listener with no firewall behind it is reachable now, today.
	sev := model.SeverityHigh
	if listenerFound && fw == firewall.StatusInactive {
		sev = model.SeverityCritical
	}

	opts := []model.FindingOption{
		model.WithService(s.in.subject()),
		model.WithDescription("The " + s.in.rt.Display + " gateway is bound to an address reachable from the network. The gateway drives an agent that can read files and run commands, so anyone who can reach this port — and get past whatever authentication is configured — is operating the agent on this host."),
		model.WithHowToFix("Bind the gateway to loopback and reach it over an SSH tunnel or a tailnet instead of exposing the port. If it must be remote, put it behind an authenticated reverse proxy and a firewall rule that allows only the addresses you use."),
		model.WithEvidence("port", strconv.Itoa(port)),
		model.WithEvidence("basis", basis),
	}
	if bind != "" {
		opts = append(opts, model.WithEvidence("bind", bind))
	}
	if listenerFound {
		opts = append(opts, model.WithEvidence("address", listener.Addr))
		if listener.Proc != "" {
			opts = append(opts, model.WithEvidence("process", listener.Proc))
		}
	}
	out := []model.Finding{model.NewFinding("agent.gateway-exposed",
		s.in.rt.Display+" gateway is reachable from the network",
		sev, model.SourceAgent, model.RemediationManual, opts...)}

	// Authentication is only judged once the gateway is actually exposed.
	// Every one of these runtimes treats "no auth on loopback" as a
	// legitimate single-user default, so flagging it would put a Critical on
	// a correct install — a score you could not improve by doing everything
	// right.
	if s.cfgKnown && gw.AuthKey != "" {
		auth := lookupString(s.cfg, gw.AuthKey)
		if ev, ok := s.in.rt.EnvOverrides[gw.AuthKey]; ok && s.envKnown {
			if v := s.env.Values[ev]; v != "" {
				auth = v
			}
		}
		if slices.Contains(gw.AuthDisabled, auth) {
			shown := auth
			if shown == "" {
				shown = "(unset)"
			}
			out = append(out, model.NewFinding("agent.auth-disabled",
				s.in.rt.Display+" gateway accepts requests with no authentication",
				model.SeverityCritical, model.SourceAgent, model.RemediationManual,
				model.WithService(s.in.subject()),
				model.WithDescription("The gateway is reachable from the network and requires no credential to talk to. Anyone who can reach the port can drive the agent: read the files it can read, run the commands it can run, and use the API keys it holds."),
				model.WithHowToFix("Set the gateway's authentication mode to a token or password with a long random value, and bind the gateway to loopback as well — authentication is the second line, not the first."),
				model.WithEvidence("setting", gw.AuthKey),
				model.WithEvidence("value", shown),
				model.WithEvidence("port", strconv.Itoa(port)),
			))
		}
	}
	return out
}

// matchListener finds a non-loopback listener for the gateway.
//
// The port is the only trigger. A process name never matches on its own,
// however tempting it is as a way to catch a gateway moved to a port we could
// not read: these runtimes are reported by ss under whatever interpreter runs
// them — python3, node, uvicorn — and matching those would attribute any
// unrelated Python or Node service on the host to an agent gateway. The
// default port is always known, so the fallback bought very little and cost a
// false positive on some of the most common process names there are.
//
// ProcNames is still used, for what it is actually good for: when several
// listeners share the port, prefer the one the runtime plausibly owns, so the
// evidence names a useful process.
func matchListener(listeners []platform.Listener, port int, procs []string) (platform.Listener, bool) {
	var first platform.Listener
	found := false
	for _, l := range listeners {
		if l.Loopback() || l.Port != port {
			continue
		}
		if l.Proc != "" && slices.Contains(procs, l.Proc) {
			return l, true
		}
		if !found {
			first, found = l, true
		}
	}
	return first, found
}

// dangerFindings applies the runtime's danger-key table. Rules sharing an ID
// are collapsed into one finding listing every key that tripped it, so an
// operator sees one problem rather than the same problem twice.
func dangerFindings(s scan) []model.Finding {
	type hit struct {
		rule DangerRule
		keys []string
	}
	byID := map[string]*hit{}
	var order []string

	for _, dr := range s.in.rt.Danger {
		v, ok := lookup(s.cfg, dr.Key)
		if !ok || !slices.Contains(dr.Bad, scalar(v)) {
			continue
		}
		if h, seen := byID[dr.ID]; seen {
			h.keys = append(h.keys, dr.Key)
			continue
		}
		byID[dr.ID] = &hit{rule: dr, keys: []string{dr.Key}}
		order = append(order, dr.ID)
	}

	out := make([]model.Finding, 0, len(order))
	for _, id := range order {
		h := byID[id]
		out = append(out, model.NewFinding(id, h.rule.Title, h.rule.Sev,
			model.SourceAgent, model.RemediationManual,
			model.WithService(s.in.subject()),
			model.WithDescription(h.rule.Desc),
			model.WithHowToFix(h.rule.HowToFix),
			model.WithEvidence("settings", strings.Join(h.keys, model.EvidenceSeparator)),
			model.WithEvidence("config", s.in.path(s.in.rt.Config)),
		))
	}
	return out
}
