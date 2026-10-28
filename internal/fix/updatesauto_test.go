package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The most ordinary hardening step on a Debian host — switching automatic
// security updates on — was Review, and only because the one fix Hostveil had
// ran `apt-get install`. On the common host the package is already there and
// the whole remediation is two lines in a config file, which is a file edit:
// reversible from a checkpoint, and something `fix --all` can do on its own.
//
// So the shape of this fix is decided by evidence, and both shapes are pinned:
// get it wrong toward exec and the fix leaves the unattended path again; get
// it wrong toward edit and Hostveil writes a config for a package that is not
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

func dnfAutomaticFinding(evidence map[string]string) model.Finding {
	opts := []model.FindingOption{model.WithEvidence("mechanism", "dnf-automatic"),
		model.WithEvidence("config", "/etc/dnf/automatic.conf")}
	for k, v := range evidence {
		opts = append(opts, model.WithEvidence(k, v))
	}
	return model.NewFinding("updates.disabled", "Automatic security updates are not enabled",
		model.SeverityMedium, model.SourceUpdates, model.RemediationReview, opts...)
}

// Installing dnf-automatic and enabling its timer was the whole fix, and on a
// real Fedora 44 that left a timer downloading updates and installing none:
// the shipped default is apply_updates = no. Every shape now sets the key.
func TestDnfAutomaticFixAlwaysTurnsOnApplying(t *testing.T) {
	for _, tc := range []struct {
		name      string
		evidence  map[string]string
		kind      model.RemediationKind
		afterArgs []string
	}{
		{"timer on, applying off", map[string]string{"installed": "true", "timer": "enabled"}, model.RemediationAuto, nil},
		{"timer off", map[string]string{"installed": "true", "timer": "disabled"}, model.RemediationReview,
			[]string{"systemctl enable --now dnf-automatic.timer"}},
		{"not installed", map[string]string{"installed": "false"}, model.RemediationReview,
			[]string{"dnf install -y dnf-automatic", "systemctl enable --now dnf-automatic.timer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx, err := buildEnableAutoUpdates(dnfAutomaticFinding(tc.evidence))
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(fx); err != nil {
				t.Fatal(err)
			}
			if got := fx.EffectiveKind(); got != tc.kind {
				t.Errorf("EffectiveKind = %v, want %v", got, tc.kind)
			}
			a := fx.Actions[0]
			if a.Kind != ActionEdit || a.Path != "/etc/dnf/automatic.conf" || !a.CreateIfMissing {
				t.Fatalf("want a create-if-missing edit of /etc/dnf/automatic.conf, got %+v", a)
			}
			var after []string
			for _, c := range a.AfterWrite {
				after = append(after, strings.Join(c, " "))
			}
			if strings.Join(after, "|") != strings.Join(tc.afterArgs, "|") {
				t.Errorf("AfterWrite = %q, want %q", after, tc.afterArgs)
			}
			if len(tc.afterArgs) > 0 && (len(a.AfterRestore) != 1 || strings.Join(a.AfterRestore[0], " ") != "systemctl disable --now dnf-automatic.timer") {
				t.Errorf("a rollback should stop the timer the fix started, got %q", a.AfterRestore)
			}
		})
	}
}

func TestSetDnfApplyUpdates(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"created", "", "[commands]\napply_updates = yes\nupgrade_type = security\n"},
		// dnf4's shipped file, abridged: the key is rewritten where it is,
		// and the operator's upgrade_type is left alone.
		{"stock dnf4", "[commands]\n# comment\nupgrade_type = default\napply_updates = no\n\n[emitters]\nemit_via = stdio\n",
			"[commands]\n# comment\nupgrade_type = default\napply_updates = yes\n\n[emitters]\nemit_via = stdio\n"},
		{"section without the key", "[commands]\nupgrade_type = security\n[base]\ndebuglevel = 1\n",
			"[commands]\napply_updates = yes\nupgrade_type = security\n[base]\ndebuglevel = 1\n"},
		{"no commands section", "[emitters]\nemit_via = motd", "[emitters]\nemit_via = motd\n\n[commands]\napply_updates = yes\n"},
		// apply_updates in another section is not this one.
		{"key elsewhere", "[base]\napply_updates = no\n", "[base]\napply_updates = no\n\n[commands]\napply_updates = yes\n"},
	} {
		got, err := setDnfApplyUpdates([]byte(tc.in))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("%s:\ngot  %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
