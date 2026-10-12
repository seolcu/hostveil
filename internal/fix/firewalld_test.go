package fix

import (
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func commandLines(fx Fix) []string {
	var out []string
	for _, c := range fx.Actions[0].Commands {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// firewalld installed and stopped: the SSH allow goes into the permanent
// configuration before the daemon starts, which is what firewall-offline-cmd
// is for — the same order as the ufw fix.
func TestEnablingFirewalldAllowsSSHFirst(t *testing.T) {
	f := model.NewFinding("firewall.inactive", "No active host firewall", model.SeverityHigh,
		model.SourceFirewall, model.RemediationReview,
		model.WithEvidence("available", "firewall-cmd, nft, iptables"), model.WithEvidence("ssh_port", "22,2222"))
	fx, err := buildEnableFirewall(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"firewall-offline-cmd --add-port=22/tcp",
		"firewall-offline-cmd --add-port=2222/tcp",
		"firewall-offline-cmd --set-target=default",
		"systemctl enable --now firewalld",
	}
	if got := commandLines(fx); !slices.Equal(got, want) {
		t.Errorf("runs %q, want %q", got, want)
	}
	if fx.EffectiveKind() != model.RemediationReview || fx.Actions[0].Warning == "" {
		t.Error("an exec fix with no checkpoint is Review and says so")
	}
}

// ufw wins when both are installed, and a Proxmox host gets neither.
func TestEnablingPrefersUFWAndNeverOnProxmox(t *testing.T) {
	both := model.NewFinding("firewall.inactive", "x", model.SeverityHigh, model.SourceFirewall, model.RemediationReview,
		model.WithEvidence("available", "ufw, firewall-cmd"), model.WithEvidence("ssh_port", "22"))
	fx, err := buildEnableFirewall(both)
	if err != nil || !strings.HasPrefix(commandLines(fx)[0], "ufw ") {
		t.Errorf("with ufw installed the fix is ufw's: %q %v", commandLines(fx), err)
	}
	pve := model.NewFinding("firewall.inactive", "x", model.SeverityHigh, model.SourceFirewall, model.RemediationReview,
		model.WithEvidence("available", "firewall-cmd, pve-firewall"), model.WithEvidence("ssh_port", "22"))
	if _, err := buildEnableFirewall(pve); err == nil {
		t.Error("firewalld was offered on a Proxmox host")
	}
}

func TestFirewalldDefaultAllowFlipsTheZoneTarget(t *testing.T) {
	f := model.NewFinding("firewall.default-allow", "x", model.SeverityHigh, model.SourceFirewall, model.RemediationReview,
		model.WithEvidence("firewall", "firewalld"), model.WithEvidence("zone", "public"), model.WithEvidence("ssh_port", "22"))
	fx, err := buildFixDefaultAllow(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(fx); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"firewall-cmd --zone=public --add-port=22/tcp",
		"firewall-cmd --permanent --zone=public --add-port=22/tcp",
		"firewall-cmd --permanent --zone=public --set-target=default",
		"firewall-cmd --reload",
	}
	if got := commandLines(fx); !slices.Equal(got, want) {
		t.Errorf("runs %q, want %q", got, want)
	}
	delete(f.Evidence, "zone")
	if _, err := buildFixDefaultAllow(f); err == nil {
		t.Error("a finding with no zone built a fix that would guess one")
	}
}
