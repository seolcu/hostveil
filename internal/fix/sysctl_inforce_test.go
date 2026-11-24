package fix

import (
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// An Auto sysctl fix tries to load the file it wrote, so on an ordinary host
// the running kernel has the value when the fix reports success and the next
// scan, which reads /proc/sys, sees it resolved.
func TestAutoSysctlLoadsTheFileItWrote(t *testing.T) {
	f := model.NewFinding("sysctl.log-martians", "Suspicious source addresses are not logged",
		model.SeverityLow, model.SourceSysctl, model.RemediationAuto,
		model.WithEvidence("set", "net.ipv4.conf.all.log_martians=1,net.ipv4.conf.default.log_martians=1"),
		model.WithEvidence("value", "net.ipv4.conf.all.log_martians=0, net.ipv4.conf.default.log_martians=0"))
	fx, err := buildSysctl(f)
	if err != nil {
		t.Fatal(err)
	}
	a := fx.Actions[0]
	if a.TakesEffectOn == "" {
		t.Error("where the kernel refuses the load, the fix still waits for a boot; TakesEffectOn must stay")
	}
	if len(a.AfterWrite) != 0 {
		t.Errorf("AfterWrite = %v; a refused load must not undo the file", a.AfterWrite)
	}
	if want := [][]string{{"sysctl", "-p", a.Path}}; !slices.EqualFunc(a.ApplyNow, want, slices.Equal) {
		t.Errorf("ApplyNow = %v, want %v", a.ApplyNow, want)
	}
	want := [][]string{
		{"sysctl", "-w", "net.ipv4.conf.all.log_martians=0"},
		{"sysctl", "-w", "net.ipv4.conf.default.log_martians=0"},
	}
	if !slices.EqualFunc(a.AfterRestore, want, slices.Equal) {
		t.Errorf("AfterRestore = %v, want the values the scan read: %v", a.AfterRestore, want)
	}
	if fx.EffectiveKind() != model.RemediationAuto {
		t.Errorf("an edit with follow-up commands is still Auto, got %v", fx.EffectiveKind())
	}
}

// With no recorded runtime value there is nothing to restore it to, and the
// rollback restores the file alone.
func TestAutoSysctlWithoutARecordedValueRestoresTheFileOnly(t *testing.T) {
	fx, err := buildSysctl(sysctlFinding(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Actions[0].AfterRestore) != 0 {
		t.Errorf("AfterRestore = %v, want nothing", fx.Actions[0].AfterRestore)
	}
}

// A protocol module nothing has loaded is Auto, and blocking it is in force
// at once. A loaded one keeps the Review floor and waits for a reboot.
func TestModuleBlockIsAutoOnlyWhenTheModuleIsNotLoaded(t *testing.T) {
	r := Default()
	for _, tc := range []struct {
		id, module, loaded string
		want               model.RemediationKind
		effect             string
	}{
		{"sysctl.module-dccp", "dccp", "no", model.RemediationAuto, ""},
		{"sysctl.module-dccp", "dccp", "yes", model.RemediationReview, "the next reboot"},
		{"sysctl.module-dccp", "dccp", "", model.RemediationReview, "the next reboot"},
		{"sysctl.module-usbstorage", "usb-storage", "no", model.RemediationReview, ""},
	} {
		opts := []model.FindingOption{
			model.WithEvidence("config", "/etc/modprobe.d/99-hostveil-hardening.conf"),
			model.WithEvidence("module", tc.module),
		}
		if tc.loaded != "" {
			opts = append(opts, model.WithEvidence("loaded", tc.loaded))
		}
		f := model.NewFinding(tc.id, "x", model.SeverityLow, model.SourceSysctl, tc.want, opts...)
		fx, ok, err := r.Build(f)
		if err != nil || !ok {
			t.Fatalf("%s: build: ok=%v err=%v", tc.id, ok, err)
		}
		if fx.Kind != tc.want {
			t.Errorf("%s loaded=%q: kind %v, want %v", tc.id, tc.loaded, fx.Kind, tc.want)
		}
		if got := fx.Actions[0].TakesEffectOn; got != tc.effect {
			t.Errorf("%s loaded=%q: TakesEffectOn %q, want %q", tc.id, tc.loaded, got, tc.effect)
		}
	}
}

// With root's password locked, prohibit-password removes no working login,
// so the fix is a single Auto action. Otherwise it stays a Review choice.
func TestRootLoginIsAutoWhenRootHasNoPassword(t *testing.T) {
	base := []model.FindingOption{model.WithEvidence("config", "/etc/ssh/sshd_config")}
	locked := model.NewFinding("ssh.rootlogin", "x", model.SeverityHigh, model.SourceSSH, model.RemediationAuto,
		append(base, model.WithEvidence("root password", "locked"))...)
	fx, err := buildRootLogin(locked)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Kind != model.RemediationAuto || len(fx.Actions) != 1 {
		t.Fatalf("locked root: kind %v with %d actions, want one Auto action", fx.Kind, len(fx.Actions))
	}
	open := model.NewFinding("ssh.rootlogin", "x", model.SeverityHigh, model.SourceSSH, model.RemediationReview, base...)
	fx, err = buildRootLogin(open)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Kind != model.RemediationReview || len(fx.Actions) != 2 {
		t.Fatalf("root with a password: kind %v with %d actions, want two Review alternatives", fx.Kind, len(fx.Actions))
	}
}
