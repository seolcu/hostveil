package fix_test

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// Actions[0] is what hostveil recommends, and it is what an operator who does
// not read the alternatives gets: every interface lists them in this order,
// the TUI and the dashboard preselect the first, and `fix --all --review`
// applies index 0 without asking.
//
// That was recorded in three prose comments and enforced by nothing. One
// builder disagreed with it — ds010 led with the *smallest* memory limit while
// the warning beside every alternative said "Start generous… and tighten
// later", so a reviewed batch capped every unlimited container at 512m.
//
// So the recommendation is named here, per fix, in words. A test that only
// asserted "the order is deterministic" would have passed throughout.
var recommendedFirst = map[string]struct{ label, why string }{
	"ssh.rootlogin": {
		label: "prohibit-password",
		why:   "keeps key-based root access working; the alternative locks root out entirely and needs another sudo user in place first",
	},
	"compose.ds010": {
		label: "1g",
		why:   "the warning on every alternative says to start generous and tighten later, so the recommendation cannot be the smallest value",
	},
	"cve.outdated-image": {
		label: "recreate",
		why:   "the alternative downloads the image and changes nothing that is running, so it does not remediate the finding on its own",
	},
	"agent.exec-unrestricted": {
		label: "deny",
		why:   "the rule table's first safe value; ask is the same door with a prompt on it",
	},
	"proxy.no-scan-jail": {
		label: "fail2ban's own default",
		why:   "a batch applying this with nobody watching should not also be the one picking the longer, harder-to-notice-and-undo ban",
	},
}

// The sysctl fixes all share one shape, so they share one entry rather than
// eight copies of it.
const sysctlRecommendedWhy = "the drop-in is file-backed, so it leaves a checkpoint and survives a reboot; `sysctl -w` does neither. " +
	"register.go argues that neither dominates for a person, and it is right — but a batch is not a person, and only one of the two can be undone."

func TestTheFirstAlternativeIsTheRecommendedOne(t *testing.T) {
	r := fix.Default()
	var checked int
	for _, id := range r.Patterns() {
		f := fixtest.Finding(id)
		fx, ok, err := r.Build(f)
		if err != nil || !ok {
			continue // builders that decline on a synthetic finding are covered elsewhere
		}
		if fx.EffectiveKind() != model.RemediationReview || len(fx.Actions) < 2 {
			continue // nothing to choose between
		}
		checked++

		want, named := recommendedFirst[id]
		if strings.HasPrefix(id, "sysctl.") {
			want, named = struct{ label, why string }{"Persist", sysctlRecommendedWhy}, true
		}
		if !named {
			t.Errorf("%s offers %d alternatives and none of them is written down as the recommendation; "+
				"`fix --all --review` applies the first without asking, so somebody has to have decided which that is",
				id, len(fx.Actions))
			continue
		}
		if got := fx.Actions[0].Label; !strings.Contains(got, want.label) {
			t.Errorf("%s recommends %q; the recommendation is the one containing %q, because %s",
				id, got, want.label, want.why)
		}
	}
	if checked == 0 {
		t.Fatal("no multi-alternative fix was reached; the walk is not building anything")
	}
}

// And the entries do not outlive the fixes they describe.
func TestNoRecommendationNamesAFixThatIsGone(t *testing.T) {
	r := fix.Default()
	for id := range recommendedFirst {
		if !r.Has(id) {
			t.Errorf("%s is named as a recommendation and is no longer registered", id)
		}
	}
}
