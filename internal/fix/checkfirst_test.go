package fix

import (
	"testing"

	"github.com/seolcu/hostveil/internal/fix/fixtest"
)

// A key that matches no registration is a sentence no one will ever see, and
// a typo in an ID is exactly how one would get there.
func TestEveryCheckFirstNamesARegisteredFix(t *testing.T) {
	r := Default()
	for id, text := range checkFirst {
		if text == "" {
			t.Errorf("%s: empty CheckFirst", id)
		}
		fx, ok, err := r.Build(fixtest.Finding(id))
		if !ok || err != nil {
			t.Errorf("%s: no fix builds for it (ok=%v, err=%v)", id, ok, err)
			continue
		}
		for i, a := range fx.Actions {
			if a.CheckFirst != text {
				t.Errorf("%s action %d: CheckFirst = %q, want the table's text", id, i, a.CheckFirst)
			}
		}
	}
}

// The fixes that can cut off the operator's own access carry one.
func TestLockoutFixesSayWhatToCheckFirst(t *testing.T) {
	for _, id := range []string{"ssh.passwordauth", "ssh.rootlogin", "firewall.inactive", "firewall.default-allow", "accounts.emptypassword", "accounts.uid0"} {
		if checkFirst[id] == "" {
			t.Errorf("%s can lock the operator out and says nothing about what to check first", id)
		}
	}
}
