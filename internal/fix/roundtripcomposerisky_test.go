package fix_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// One service carrying every setting the risky compose fixes remove, so each
// fix is checked against the others still standing: clearing its own finding
// is not enough, it must leave every neighbour exactly as it was.
const composeRisky = `services:
  app:
    image: example/app:1.0   # not a datastore, so ds018 stays quiet
    privileged: true
    network_mode: host
    pid: host
    ipc: host
    userns_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    security_opt:
      - seccomp:unconfined
      - apparmor:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host/etc
`

var composeRiskyIDs = []string{
	"compose.ds001", "compose.ds005", "compose.dr001", "compose.ds020",
	"compose.ds021", "compose.ds026", "compose.ds023", "compose.ds024",
	"compose.ds016", "compose.ds017", "compose.ds022", "compose.ds009",
}

// riskyHost is a host carrying composeRisky, read through the runner the
// compose checker discovers projects with.
type riskyHost struct {
	checker *composecheck.Checker
	runner  *checktest.Runner
}

func composeRiskyHost(t *testing.T, dir string) riskyHost {
	t.Helper()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(composeRisky), 0o600); err != nil {
		t.Fatal(err)
	}
	return riskyHost{checker: composecheck.New(), runner: checktest.ComposeProjects(map[string]string{"stack": path})}
}

func TestEveryRiskyComposeFixClearsItsFindingAndNoOther(t *testing.T) {
	for _, id := range composeRiskyIDs {
		t.Run(id, func(t *testing.T) {
			checker := composeRiskyHost(t, t.TempDir())
			before := runRisky(t, checker)
			f, ok := before[id]
			if !ok {
				t.Fatalf("the checker did not flag %s on a host built to trip it; it found %v", id, keysOf(before))
			}
			in, out := applyFirstAlternative(t, f)
			after := runRisky(t, checker)

			// The cap_add rule reports the first dangerous capability it
			// meets, so dropping NET_ADMIN surfaces SYS_ADMIN under the same
			// ID. That is the next finding, not this one surviving.
			if g, still := after[id]; still && g.Evidence["capability"] == f.Evidence["capability"] {
				t.Errorf("%s survived its own fix.\n--- before ---\n%s\n--- after ---\n%s", id, in, out)
			}
			for other := range before {
				if other == id {
					continue
				}
				if _, ok := after[other]; !ok {
					t.Errorf("fixing %s also cleared %s.\n--- after ---\n%s", id, other, out)
				}
			}
			for other := range after {
				if _, ok := before[other]; ok {
					continue
				}
				t.Errorf("fixing %s introduced %s.\n--- after ---\n%s", id, other, out)
			}
		})
	}
}

// Every one of these is offered only on its own. A reviewed batch applies the
// first alternative of anything Review without asking, and these are Review
// precisely because somebody has to ask.
func TestRiskyComposeFixesAreReviewAndIndividualOnly(t *testing.T) {
	checker := composeRiskyHost(t, t.TempDir())
	found := runRisky(t, checker)
	for _, id := range composeRiskyIDs {
		f, ok := found[id]
		if !ok {
			t.Errorf("%s not flagged", id)
			continue
		}
		fx, ok, err := fix.Default().Build(f)
		if err != nil || !ok {
			t.Errorf("%s: build ok=%v err=%v", id, ok, err)
			continue
		}
		if fx.EffectiveKind() != model.RemediationReview {
			t.Errorf("%s is %v; a fix that can break a deployment is Review", id, fx.EffectiveKind())
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

func runRisky(t *testing.T, h riskyHost) map[string]model.Finding {
	t.Helper()
	fs, err := h.checker.Check(context.Background(), h.runner.Env())
	var pe *check.PartialError
	if err != nil && !errors.As(err, &pe) {
		t.Fatalf("compose check: %v", err)
	}
	out := map[string]model.Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}
