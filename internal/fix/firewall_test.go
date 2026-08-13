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

// Two ports at once is how an operator changes the SSH port without locking
// themselves out: `Port 22` and `Port 2222` both listening, verify the new
// one, then drop the old. The fix allowed the first and `ufw --force enable`
// severed the second, with no checkpoint to undo it — on a host reached only
// over SSH.
//
// The whole justification for this fix existing is that hostveil now knows
// which port to keep open. It knew one of them.
func TestTheFirewallFixAllowsEverySSHPortBeforeItClosesEverything(t *testing.T) {
	f := model.NewFinding("firewall.inactive", "t", model.SeverityHigh, model.SourceFirewall,
		model.RemediationReview,
		model.WithEvidence("ssh_port", "22,2222"),
		model.WithEvidence("available", "ufw"))

	fx, err := buildEnableFirewall(f)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cmds := fx.Actions[0].Commands
	if len(cmds) != 3 {
		t.Fatalf("got %d commands, want an allow per port plus the enable: %v", len(cmds), cmds)
	}
	for i, want := range [][]string{
		{"ufw", "allow", "22/tcp"},
		{"ufw", "allow", "2222/tcp"},
		{"ufw", "--force", "enable"},
	} {
		if strings.Join(cmds[i], " ") != strings.Join(want, " ") {
			t.Errorf("command %d is %v, want %v — every port has to be open before the policy closes", i, cmds[i], want)
		}
	}
	if !strings.Contains(fx.Actions[0].Warning, "2222") {
		t.Errorf("the warning does not name both ports: %q", fx.Actions[0].Warning)
	}
}

// A list hostveil cannot fully parse is one it cannot fully allow, and
// allowing the part it understood before a default-deny policy is how the
// rest gets severed.
func TestTheFirewallFixRefusesAPartlyReadablePortList(t *testing.T) {
	for _, raw := range []string{"22,", "22,nonsense", "", "0"} {
		f := model.NewFinding("firewall.inactive", "t", model.SeverityHigh, model.SourceFirewall,
			model.RemediationReview,
			model.WithEvidence("ssh_port", raw),
			model.WithEvidence("available", "ufw"))
		if _, err := buildEnableFirewall(f); err == nil {
			t.Errorf("ssh_port=%q built a fix; a port list that does not fully parse must not enable a default-deny policy", raw)
		}
	}
}
