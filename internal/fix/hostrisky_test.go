package fix_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// The findings that used to be declined for a risk the checker cannot weigh,
// and are now offered with that risk stated. Each must be Review, applied only
// on its own, and say on every alternative what it can break.
var individualOnly = []string{
	"updates.reboot-required", "accounts.uid0", "accounts.weak-password-hash",
	"systemd.private-tmp", "systemd.protect-home", "systemd.protect-system",
	"systemd.private-devices", "systemd.protect-kernel-tunables",
	"systemd.protect-control-groups", "systemd.restrict-namespaces",
	"systemd.memory-deny-write-execute",
}

func TestRiskyHostFixesAreReviewAndIndividualOnly(t *testing.T) {
	for _, id := range individualOnly {
		fx, ok, err := fix.Default().Build(fixtest.Finding(id))
		if err != nil || !ok {
			t.Errorf("%s: build ok=%v err=%v", id, ok, err)
			continue
		}
		if fx.Kind != model.RemediationReview {
			t.Errorf("%s declares %v; the registry is read as the screen value, so it must say Review itself", id, fx.Kind)
		}
		if !fx.IndividualOnly {
			t.Errorf("%s is not IndividualOnly, so `fix --all --review` would apply it unread", id)
		}
		for i, a := range fx.Actions {
			if a.Warning == "" {
				t.Errorf("%s action %d has no Warning", id, i)
			}
		}
	}
}

// The reboot is scheduled, never immediate: an immediate reboot kills the
// process applying it before the fix is recorded, and leaves the operator no
// window to cancel.
func TestTheRebootIsScheduledAndCancellable(t *testing.T) {
	fx, _, err := fix.Default().Build(fixtest.Finding("updates.reboot-required"))
	if err != nil {
		t.Fatal(err)
	}
	argv := fx.Actions[0].Commands[0]
	if argv[0] != "shutdown" || argv[1] != "-r" || !strings.HasPrefix(argv[2], "+") {
		t.Errorf("reboot argv = %v, want a delayed `shutdown -r +N`", argv)
	}
	if !strings.Contains(fx.Actions[0].Warning, "shutdown -c") {
		t.Error("the warning must say how to cancel the reboot")
	}
}

// Locking comes first because it keeps the evidence and can be undone; the
// account named is the first of the list, so one button touches one account.
func TestRogueRootIsLockedBeforeItIsDeleted(t *testing.T) {
	f := fixtest.Finding("accounts.uid0")
	f.Evidence["accounts"] = "backdoor, toor"
	fx, _, err := fix.Default().Build(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := fx.Actions[0].Commands[0]; !slices.Equal(got, []string{"usermod", "--lock", "--expiredate", "1", "backdoor"}) {
		t.Errorf("first alternative runs %v", got)
	}
	if got := fx.Actions[1].Commands[0]; !slices.Equal(got, []string{"userdel", "backdoor"}) {
		t.Errorf("second alternative runs %v; it must not pass -r and take the home directory", got)
	}
}

func TestWeakHashExpiresThePasswordRatherThanSettingOne(t *testing.T) {
	f := fixtest.Finding("accounts.weak-password-hash")
	f.Evidence["accounts"] = "carol"
	fx, _, err := fix.Default().Build(f)
	if err != nil {
		t.Fatal(err)
	}
	if got := fx.Actions[0].Commands[0]; !slices.Equal(got, []string{"passwd", "--expire", "carol"}) {
		t.Errorf("runs %v", got)
	}
	if fx.Actions[0].TakesEffectOn == "" {
		t.Error("the hash changes only at the next password change, so the fix must say it is not yet in force")
	}
}

// The risky systemd fixes write the same drop-in as the six that were always
// registered, with the directive the checker asks for.
func TestRiskySystemdFixesWriteTheDirectiveTheCheckerWants(t *testing.T) {
	for id, line := range map[string]string{
		"systemd.protect-system":            "ProtectSystem=full",
		"systemd.memory-deny-write-execute": "MemoryDenyWriteExecute=yes",
		"systemd.private-tmp":               "PrivateTmp=yes",
	} {
		fx, _, err := fix.Default().Build(fixtest.Finding(id))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		out, err := fx.Actions[0].Transform(nil)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if string(out) != "[Service]\n"+line+"\n" {
			t.Errorf("%s writes %q", id, out)
		}
	}
}
