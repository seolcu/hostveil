package firewall

import (
	"context"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// The probe answers "is a firewall running", and for two of the four
// front-ends that was the whole test. nftables and iptables have to show a
// base chain whose default policy drops or rejects — hasHostFirewall and
// hasDropPolicy both insist on it — while ufw was accepted on the strength
// of "Status: active" and firewalld on `--state` exiting 0.
//
// So hostveil held a hand-written ruleset to a stricter standard than the
// two managed front-ends. `ufw enable` after `ufw default allow incoming`
// produced a perfect score on the third-heaviest axis while the host
// accepted everything, which is the same posture that scores 0 through
// firewall.inactive when nftables is the tool in use. A firewall that is
// running and permitting is not a firewall; it is a log.
//
// This closes that. It asks the same question of the two managed
// front-ends that the other two already had to answer, and — like every
// other probe here — reports "cannot tell" rather than guessing when the
// query fails.

// inboundPolicy is what the active front-end does with a packet no rule
// matched.
type inboundPolicy int

const (
	// policyUnknown means the front-end could not be queried. Almost always
	// missing root, and never evidence of either answer.
	policyUnknown inboundPolicy = iota
	// policyDeny means unmatched inbound traffic is dropped or rejected.
	policyDeny
	// policyAllow means it is accepted.
	policyAllow
)

// defaultInbound reports the active firewall's default inbound policy.
//
// which is the front-end probe() reported active, and it decides how the
// question is asked. nftables and iptables need no query at all: probe
// only calls them active when it has already seen a drop or reject policy
// on the input hook, so asking again could only produce a different answer
// by reading something else.
func defaultInbound(ctx context.Context, r platform.CommandRunner, which string) inboundPolicy {
	switch which {
	case "ufw":
		out, err := r.Run(ctx, "ufw", "status", "verbose")
		if err != nil {
			return policyUnknown
		}
		return parseUFWDefault(string(out))
	case "firewalld":
		zone, err := r.Run(ctx, "firewall-cmd", "--get-default-zone")
		if err != nil {
			return policyUnknown
		}
		name := strings.TrimSpace(string(zone))
		if name == "" {
			return policyUnknown
		}
		out, err := r.Run(ctx, "firewall-cmd", "--zone="+name, "--list-all")
		if err != nil {
			return policyUnknown
		}
		return parseFirewalldTarget(string(out))
	default:
		return policyDeny
	}
}

// parseUFWDefault reads the incoming half of ufw's default line:
//
//	Default: deny (incoming), allow (outgoing), disabled (routed)
//
// Only the incoming direction is read. Outgoing defaults to allow on
// essentially every host and denying it is a deliberate, unusual choice —
// flagging it would accuse the overwhelming majority of correct
// configurations.
func parseUFWDefault(out string) inboundPolicy {
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "default:") {
			continue
		}
		for _, part := range strings.Split(strings.TrimPrefix(line, "default:"), ",") {
			if !strings.Contains(part, "(incoming)") {
				continue
			}
			switch {
			case strings.Contains(part, "deny"), strings.Contains(part, "reject"):
				return policyDeny
			case strings.Contains(part, "allow"):
				return policyAllow
			}
		}
	}
	// The line is there on every ufw version that supports `status verbose`.
	// Its absence means the output is not what this parser was written for,
	// which is "cannot tell" — not "allow".
	return policyUnknown
}

// parseFirewalldTarget reads the zone target from `firewall-cmd --list-all`:
//
//	public (active)
//	  target: default
//
// Only an explicit ACCEPT target permits unmatched inbound traffic.
// "default" is firewalld's own name for reject, and DROP and %%REJECT%% say
// so outright.
func parseFirewalldTarget(out string) inboundPolicy {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "target:") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(line, "target:")), "ACCEPT") {
			return policyAllow
		}
		return policyDeny
	}
	return policyUnknown
}

// defaultAllowFinding reports a firewall that runs and permits.
//
// It carries the same level as firewall.inactive, because it is the same
// posture — the difference is only that this one looks fixed. The level says
// the backstop is missing, not that an exposure is confirmed: the host may
// well be behind a router or a cloud security group, which is why the
// description says so rather than the severity pretending to know.
//
// The fix carries the same reason firewall.inactive's does, and the same
// resolution: with the port sshd is actually listening on in evidence, it
// can allow that port first and only then flip the default policy, as two
// commands of one action. It stays Review — the change cannot be rolled back
// and it takes every other inbound port with it, which an operator should
// decide rather than discover — and, like firewall.inactive, it is only
// buildable for ufw; firewalld's target flip has no such fix registered yet.
func defaultAllowFinding(which string) model.Finding {
	how := "Run `ufw default deny incoming`, then `ufw reload`. Make sure your SSH port is allowed first (`ufw allow OpenSSH`) — the deny policy takes effect immediately and an unallowed session is the one you are using."
	if which == "firewalld" {
		how = "Set the default zone's target to something other than ACCEPT (`firewall-cmd --permanent --zone=<zone> --set-target=default`, then `firewall-cmd --reload`). Make sure the ssh service is allowed in that zone first — the new target takes effect immediately."
	}
	return model.NewFinding("firewall.default-allow",
		"Firewall is running but accepts everything by default",
		model.SeverityHigh, model.SourceFirewall, model.RemediationReview,
		model.WithDescription("A firewall is active, but its default policy for inbound traffic is to accept. Every port a service binds to a non-loopback address is reachable from any network this host is on, exactly as if no firewall were running — the difference is that `"+which+"` reports it as active, so the host looks protected. A firewall is only a backstop if what it does with traffic no rule matched is refuse it."),
		model.WithHowToFix(how),
		model.WithEvidence("firewall", which),
		model.WithEvidence("default_inbound", "allow"),
	)
}
