package fix_test

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
)

// A compose file is not what docker is running from. It is what docker was
// told, once — the container keeps its own configuration until it is
// recreated.
//
// So every compose edit is correct and not yet in force, and every one of them
// has to say so. This is the direction that was wrong in the worst possible
// way: the highest-severity fix in the domain claimed "After this, the service
// is reachable only from this host", which was false at apply time and stayed
// false indefinitely, while buildRepullImage — the *least* severe finding in
// the same file — had the honest sentence all along.
func TestEveryComposeEditSaysItIsNotInForceYet(t *testing.T) {
	r := fix.Default()
	var checked int
	for _, id := range r.Patterns() {
		if !strings.HasPrefix(id, "compose.") {
			continue
		}
		fx, ok, err := r.Build(fixtest.Finding(id))
		if err != nil || !ok {
			continue
		}
		for i, a := range fx.Actions {
			if a.Kind != fix.ActionEdit {
				continue
			}
			checked++
			if a.TakesEffectOn == "" {
				t.Errorf("%s action %d edits a compose file and does not say what puts the change into force; "+
					"the re-check will read the file it just wrote and report the finding gone", id, i)
			}
			if !strings.Contains(a.Warning, "recreate") && !strings.Contains(a.Warning, "up -d") {
				t.Errorf("%s action %d does not tell the operator the container is unchanged until it is recreated: %q",
					id, i, a.Warning)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no compose edit action was reached; the walk is not building anything")
	}
}

// And nothing claims the opposite. The sentence this replaced is pinned by
// name, because it is the one that was on the screen.
func TestNoFixClaimsAnEffectItHasNotHad(t *testing.T) {
	r := fix.Default()
	for _, id := range r.Patterns() {
		fx, ok, err := r.Build(fixtest.Finding(id))
		if err != nil || !ok {
			continue
		}
		for i, a := range fx.Actions {
			if strings.Contains(a.Warning, "After this, the service is reachable only from this host") {
				t.Errorf("%s action %d is back to claiming an effect it does not have until the container is recreated", id, i)
			}
		}
	}
}

// An edit that is in force the moment it is written must not declare
// otherwise, or every fix would report pending and the state would stop
// meaning anything. sshd_config is the case: the file is the artifact the
// checker reads *and* what sshd loads at its next start, and the ssh domain
// is the one register.go names as honest for exactly that reason.
func TestAnImmediateEditDoesNotClaimToBePending(t *testing.T) {
	r := fix.Default()
	for _, id := range r.Patterns() {
		if !strings.HasPrefix(id, "ssh.") && !strings.HasPrefix(id, "fileperms.") {
			continue
		}
		fx, ok, err := r.Build(fixtest.Finding(id))
		if err != nil || !ok {
			continue
		}
		for i, a := range fx.Actions {
			if a.TakesEffectOn != "" {
				t.Errorf("%s action %d declares it takes effect on %q; this edit is the artifact the checker reads",
					id, i, a.TakesEffectOn)
			}
		}
	}
}
