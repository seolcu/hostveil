package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func firewallFinding(opts ...model.FindingOption) model.Finding {
	base := []model.FindingOption{
		model.WithEvidence("available", "ufw"),
		model.WithEvidence("ssh_port", "22"),
	}
	return model.NewFinding("firewall.inactive", "No active host firewall", model.SeverityHigh,
		model.SourceFirewall, model.RemediationReview, append(base, opts...)...)
}

// The order is the fix. Enabling a default-deny policy first and allowing SSH
// second is the lockout this refused to risk for years, so the commands are
// asserted in sequence rather than as a set.
func TestTheFirewallFixOpensSSHBeforeItClosesEverything(t *testing.T) {
	fx, err := buildEnableFirewall(firewallFinding(model.WithEvidence("ssh_port", "2222")))
	if err != nil {
		t.Fatalf("no fix for a finding that names the port: %v", err)
	}
	// Declared Auto (one mechanical action) and demoted by the exec floor:
	// what a user is offered is Review, and it must never be anything else,
	// because `fix --all` would then enable a firewall unattended.
	if fx.Kind != model.RemediationAuto {
		t.Errorf("Kind = %v, want the declared Auto that Validate accepts for a single action", fx.Kind)
	}
	if got := fx.EffectiveKind(); got != model.RemediationReview {
		t.Errorf("EffectiveKind = %v, want Review — this cannot be rolled back", got)
	}
	if len(fx.Actions) != 1 {
		t.Fatalf("want one action carrying both commands in order, got %d", len(fx.Actions))
	}
	cmds := fx.Actions[0].Commands
	if len(cmds) != 2 {
		t.Fatalf("want two commands, got %v", cmds)
	}
	if strings.Join(cmds[0], " ") != "ufw allow 2222/tcp" {
		t.Errorf("first command is %q, want the SSH port allowed first", strings.Join(cmds[0], " "))
	}
	if strings.Join(cmds[1], " ") != "ufw --force enable" {
		t.Errorf("second command is %q, want the policy enabled second", strings.Join(cmds[1], " "))
	}
	if fx.Actions[0].Warning == "" {
		t.Error("no warning on a fix that stops every other inbound port answering")
	}
}

// "I could not tell" must not quietly become 22. A host running sshd on 2222
// whose port hostveil failed to read would be locked out by a fix that
// guessed, and the guess would look exactly like knowledge.
func TestNoFirewallFixWithoutTheSSHPort(t *testing.T) {
	for _, tc := range []struct{ name, port string }{
		{"absent", ""},
		{"unparseable", "ssh"},
		{"out of range", "70000"},
	} {
		f := firewallFinding()
		f.Evidence["ssh_port"] = tc.port
		if tc.port == "" {
			delete(f.Evidence, "ssh_port")
		}
		if _, err := buildEnableFirewall(f); err == nil {
			t.Errorf("%s: a fix was offered without a usable SSH port", tc.name)
		}
	}
}

// ufw is the only front-end whose rule syntax this writes. nftables and
// firewalld take rules that differ enough that a guessed one is a lockout by
// another route.
func TestNoFirewallFixWithoutUfw(t *testing.T) {
	f := firewallFinding()
	f.Evidence["available"] = "nftables, iptables"
	if _, err := buildEnableFirewall(f); err == nil {
		t.Error("a fix was offered for a host with no ufw")
	}
}
