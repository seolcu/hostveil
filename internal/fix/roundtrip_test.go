package fix_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	sshcheck "github.com/seolcu/hostveil/internal/check/ssh"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// The instrument this repository did not have.
//
// Every other test of a fix asks whether it errors, or compares its output to
// a string written down beside it. None of them closes the loop: take a host
// the *real* checker flags, apply the *real* registered fix, hand the result
// back to the *same* checker, and require the finding to be gone.
//
// That gap is why "does this fix actually remediate the finding?" is a
// question the suite could not answer. TestEveryRegisteredFixIsValid checks
// shape, so a Transform returning its input unchanged passes it.
// internal/core/recheck_test.go exercises the verification machinery against a
// stub whose fix writes the literal bytes "fixed\n". Neither has ever seen a
// real checker read a real fix's output.
//
// What it catches: a fix that edits the wrong key, the wrong file, or nothing
// at all — anything that leaves the finding standing, and anything that clears
// it by reaching further than it claimed to.
//
// What it cannot catch, and the limit is worth writing down because it is not
// obvious: a checker reading the wrong artifact in the first place. The loop
// uses one oracle at both ends, so a fix that satisfies a checker which is
// itself looking at the wrong file passes here. internal/check/updates is
// exactly that shape — it reads one file out of apt.conf.d while apt reads the
// whole directory, last assignment winning — and it is deliberately absent
// from the table below rather than added to it green.
//
// SSH is where this starts because internal/fix/register.go names it as the
// honest case: "the ssh checker reads sshd_config, which is the same artifact
// the ssh fix edits." A domain that is supposed to be sound is the right place
// to prove the instrument before pointing it at one that is not.

// roundTrip is one fix's loop: a host the checker flags, and the file the fix
// is expected to edit.
type roundTrip struct {
	// want is the finding ID the fix must clear.
	want string
	// setup writes the host and returns the checker that reads it.
	setup func(t *testing.T, dir string) check.Checker
	// unlocks names findings this fix is expected to *reveal*, with the
	// reason. A fix that uncovers the next door is not a fix that broke
	// something, but the two are indistinguishable to a test that simply
	// forbids new findings — so each one is written down and argued rather
	// than allowed in general.
	unlocks map[string]string
}

// sshdBad trips six rules at once, so the "and no other" direction below has
// something it could get wrong.
const sshdBad = `PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
LoginGraceTime 300
`

func roundTripCases() []roundTrip {
	setup := func(t *testing.T, dir string) check.Checker {
		t.Helper()
		path := filepath.Join(dir, "sshd_config")
		if err := os.WriteFile(path, []byte(sshdBad), 0o600); err != nil {
			t.Fatal(err)
		}
		return &sshcheck.Checker{ConfigPath: path}
	}
	unlocks := map[string]map[string]string{
		// The ssh checker emits this one only in the contradiction case, and
		// says so: "PasswordAuthentication no is meant to end password
		// guessing, but keyboard-interactive runs the same PAM password
		// prompt through a different door." So it cannot be reported until
		// the passwordauth fix has been applied — the second door is not a
		// finding while the first is standing open.
		"ssh.passwordauth": {"ssh.kbdinteractive": "PasswordAuthentication no is what makes keyboard-interactive the remaining password path"},
	}
	ids := []string{
		"ssh.emptypasswords", "ssh.maxauthtries", "ssh.x11forwarding",
		"ssh.logingracetime", "ssh.passwordauth", "ssh.rootlogin",
	}
	out := make([]roundTrip, 0, len(ids))
	for _, id := range ids {
		out = append(out, roundTrip{want: id, setup: setup, unlocks: unlocks[id]})
	}
	return out
}

func TestEveryFixActuallyClearsTheFindingItClaimsToFix(t *testing.T) {
	for _, tc := range roundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			checker := tc.setup(t, dir)

			before := runChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s on a host built to trip it; it found %v",
					tc.want, keysOf(before))
			}

			in, out := applyFirstAlternative(t, f)
			after := runChecker(t, checker)
			if _, still := after[tc.want]; still {
				t.Errorf("%s survived its own fix.\n--- before ---\n%s\n--- after ---\n%s",
					tc.want, in, out)
			}
		})
	}
}

// Clearing its own finding is necessary and not sufficient: a transform that
// emptied the file would also clear it. So nothing else the checker was
// reporting may vanish, and nothing new may appear.
func TestAFixClearsItsOwnFindingAndNoOther(t *testing.T) {
	for _, tc := range roundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			checker := tc.setup(t, dir)

			before := runChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s", tc.want)
			}
			applyFirstAlternative(t, f)
			after := runChecker(t, checker)

			for id := range before {
				if id == tc.want {
					continue
				}
				if _, ok := after[id]; !ok {
					t.Errorf("fixing %s also cleared %s, which it does not claim to fix", tc.want, id)
				}
			}
			for id := range after {
				if _, ok := before[id]; ok {
					continue
				}
				if why, expected := tc.unlocks[id]; expected {
					t.Logf("fixing %s revealed %s, as intended: %s", tc.want, id, why)
					continue
				}
				t.Errorf("fixing %s introduced %s, which is not in its unlocks list", tc.want, id)
			}
			for id, why := range tc.unlocks {
				if _, ok := after[id]; !ok {
					t.Errorf("fixing %s no longer reveals %s (%s); the entry has gone stale", tc.want, id, why)
				}
			}
		})
	}
}

// applyFirstAlternative builds the registered fix, runs its first action's
// transform over the file that action names, and writes the result back. It
// returns the bytes before and after so a failure can print both.
//
// The first alternative deliberately: it is the one a batch applies, and the
// one every builder is supposed to put its primary remediation in.
func applyFirstAlternative(t *testing.T, f model.Finding) (before, after []byte) {
	t.Helper()
	fx, ok, err := fix.Default().Build(f)
	if err != nil {
		t.Fatalf("building the fix for %s: %v", f.ID, err)
	}
	if !ok {
		t.Fatalf("no fix is registered for %s", f.ID)
	}
	if len(fx.Actions) == 0 {
		t.Fatalf("the fix for %s has no actions", f.ID)
	}
	a := fx.Actions[0]
	if a.Transform == nil {
		t.Fatalf("%s's first action is not a file edit, so this loop cannot close over it", f.ID)
	}

	before, err = os.ReadFile(a.Path)
	if err != nil {
		t.Fatalf("reading %s: %v", a.Path, err)
	}
	after, err = a.Transform(before)
	if err != nil {
		t.Fatalf("%s's transform: %v", f.ID, err)
	}
	if string(after) == string(before) {
		t.Fatalf("%s's transform returned its input unchanged", f.ID)
	}
	if err := os.WriteFile(a.Path, after, 0o600); err != nil {
		t.Fatal(err)
	}
	return before, after
}

func runChecker(t *testing.T, c check.Checker) map[string]model.Finding {
	t.Helper()
	env := checktest.New().Env()
	if ok, why := c.Available(context.Background(), env); !ok {
		t.Fatalf("the checker is unavailable: %s", why)
	}
	fs, err := c.Check(context.Background(), env)
	// A partial result still carries findings, and a domain that covered only
	// part of its ground is not a failed run — the same reading the scan uses.
	var pe *check.PartialError
	if err != nil && !errors.As(err, &pe) {
		t.Fatalf("the checker failed: %v", err)
	}
	out := map[string]model.Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

func keysOf(m map[string]model.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
