package fileperms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// The mode rules answer "how much access do the bits grant" and stopped
// there, which is only half the question. Mode 0600 grants everything to
// the owner and nothing to anyone else — so a /etc/shadow at 0600 owned by
// an ordinary user hands that user every password hash on the host, and the
// mode check calls it clean because 0600 is exactly what it wants to see.
// That is a false clean, the failure class this whole tool is built to
// refuse.

// ownerFixture builds a checker over one file. wrongOwner decides whether
// the checker expects an owner the file does not have, so both directions
// are exercised whoever runs the suite — under root and under CI's
// unprivileged user alike.
func ownerFixture(t *testing.T, mode os.FileMode, wrongOwner bool) (*Checker, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte("root:!:20000:0:99999:7:::\n"), mode); err != nil {
		t.Fatal(err)
	}
	// Chmod explicitly: WriteFile's perm is masked by umask, and this test
	// is about exact bits.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	want := os.Geteuid()
	if wrongOwner {
		want++ // an account the file certainly does not belong to
	}
	return &Checker{OwnerUID: want, Rules: []Rule{{
		Path: path, MaxMode: 0o640, Sev: model.SeverityHigh, ID: "fileperms.shadow",
		Title: "t", Desc: "d",
	}}}, path
}

func runOwner(t *testing.T, c *Checker) []model.Finding {
	t.Helper()
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func hasFinding(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

// The tests run as whatever uid the suite runs as. Under root that is 0 and
// the fixture is correctly owned; unprivileged, it is not — which is the
// interesting case and the one CI actually exercises.
func TestOwnershipIsCheckedIndependentlyOfMode(t *testing.T) {
	for name, wrong := range map[string]bool{"correctly owned": false, "wrongly owned": true} {
		t.Run(name, func(t *testing.T) {
			c, _ := ownerFixture(t, 0o600, wrong)
			fs := runOwner(t, c)

			// Impeccable bits, so the mode rule stays quiet either way —
			// which is exactly why the mode check alone called this clean.
			if hasFinding(fs, "fileperms.shadow") {
				t.Errorf("a 0600 file was flagged for its mode: %v", fs)
			}
			if got := hasFinding(fs, ownerFindingID); got != wrong {
				t.Errorf("owner finding fired = %v, want %v", got, wrong)
			}
		})
	}
}

// A file with both problems produces both findings: they are different
// questions with different remediations, and collapsing them would hide one.
func TestModeAndOwnerAreSeparateFindings(t *testing.T) {
	c, _ := ownerFixture(t, 0o666, true)
	fs := runOwner(t, c)

	for _, id := range []string{"fileperms.shadow", ownerFindingID} {
		if !hasFinding(fs, id) {
			t.Errorf("%s did not fire on a file that is both loose and wrongly owned: %v", id, fs)
		}
	}
}

// The finding has to name the files and carry a remediation a person can
// act on — and say the group is not guessable, because /etc/shadow is
// root:shadow on Debian and root:root elsewhere.
func TestOwnerFindingIsActionable(t *testing.T) {
	c, path := ownerFixture(t, 0o600, true)
	var owner model.Finding
	for _, f := range runOwner(t, c) {
		if f.ID == ownerFindingID {
			owner = f
		}
	}
	if owner.ID == "" {
		t.Fatal("no owner finding")
	}
	if err := owner.Validate(); err != nil {
		t.Fatalf("invalid finding: %v", err)
	}
	if !strings.Contains(owner.Evidence["files"], path) {
		t.Errorf("the evidence does not name the file: %q", owner.Evidence["files"])
	}
	if !strings.Contains(owner.HowToFix, "chown root:root "+path) {
		t.Errorf("the how-to-fix does not carry a runnable command: %q", owner.HowToFix)
	}
	if !strings.Contains(owner.HowToFix, "group") {
		t.Errorf("the how-to-fix does not mention the group, which differs by distribution: %q", owner.HowToFix)
	}
	// Manual on purpose: chown has no checkpoint. The register says why.
	if owner.Remediation != model.RemediationManual {
		t.Errorf("remediation = %v, want Manual", owner.Remediation)
	}
}

// A missing file is not a finding, here as everywhere else in this checker:
// no SSH server means no host keys, not a problem with the host keys.
func TestAMissingFileHasNoOwner(t *testing.T) {
	c := &Checker{OwnerUID: os.Geteuid() + 1, Rules: []Rule{{
		Path: filepath.Join(t.TempDir(), "absent"), MaxMode: 0o600,
		Sev: model.SeverityHigh, ID: "fileperms.shadow", Title: "t", Desc: "d",
	}}}
	if fs := runOwner(t, c); len(fs) != 0 {
		t.Errorf("a missing file produced %v", fs)
	}
}
