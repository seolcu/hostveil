package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The most ordinary hardening step on a Debian host — switching automatic
// security updates on — was Review, and only because the one fix hostveil had
// ran `apt-get install`. On the common host the package is already there and
// the whole remediation is two lines in a config file, which is a file edit:
// reversible from a checkpoint, and something `fix --all` can do on its own.
//
// So the shape of this fix is decided by evidence, and both shapes are pinned:
// get it wrong toward exec and the fix leaves the unattended path again; get
// it wrong toward edit and hostveil writes a config for a package that is not
// installed, which enables nothing and reports success.
func TestAutoUpdatesIsAnEditWhenTheMechanismIsAlreadyInstalled(t *testing.T) {
	installed := model.NewFinding("updates.disabled", "Automatic security updates are not enabled",
		model.SeverityMedium, model.SourceUpdates, model.RemediationAuto,
		model.WithEvidence("mechanism", "unattended-upgrades"),
		model.WithEvidence("installed", "true"),
		model.WithEvidence("config", "/etc/apt/apt.conf.d/20auto-upgrades"))

	fx, err := buildEnableAutoUpdates(installed)
	if err != nil {
		t.Fatalf("no fix for an installed mechanism: %v", err)
	}
	if got := fx.EffectiveKind(); got != model.RemediationAuto {
		t.Errorf("EffectiveKind = %v, want Auto — an edit needs no human", got)
	}
	if len(fx.Actions) != 1 || fx.Actions[0].Kind != ActionEdit {
		t.Fatalf("want one edit action, got %+v", fx.Actions)
	}
	if !fx.Actions[0].CreateIfMissing {
		t.Error("a host that never configured automatic updates has no 20auto-upgrades to edit")
	}

	// Both keys, because setting only the unattended one gives a host that
	// faithfully applies updates it never learns about.
	out, err := fx.Actions[0].Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`APT::Periodic::Update-Package-Lists "1";`, `APT::Periodic::Unattended-Upgrade "1";`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the new file does not contain %q:\n%s", want, out)
		}
	}

	// An existing assignment is rewritten, not appended to: apt reads the last
	// one, so appending leaves the file saying both things.
	out, err = fx.Actions[0].Transform([]byte("APT::Periodic::Update-Package-Lists \"0\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), "APT::Periodic::Unattended-Upgrade") != 1 {
		t.Errorf("the key is assigned more than once:\n%s", out)
	}
	if strings.Contains(string(out), `"0"`) {
		t.Errorf("an old value survived:\n%s", out)
	}
}

func TestAutoUpdatesStillInstallsWhenTheMechanismIsMissing(t *testing.T) {
	missing := model.NewFinding("updates.disabled", "Automatic security updates are not enabled",
		model.SeverityMedium, model.SourceUpdates, model.RemediationAuto,
		model.WithEvidence("mechanism", "unattended-upgrades"))

	fx, err := buildEnableAutoUpdates(missing)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Actions[0].Kind != ActionExec {
		t.Fatalf("want an exec action to install the package, got %v", fx.Actions[0].Kind)
	}
	if got := fx.EffectiveKind(); got != model.RemediationReview {
		t.Errorf("EffectiveKind = %v, want Review — an install has no checkpoint", got)
	}
}
