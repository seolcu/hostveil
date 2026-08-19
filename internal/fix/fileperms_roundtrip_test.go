package fix_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	filepermscheck "github.com/seolcu/hostveil/internal/check/fileperms"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// filepermsRoundTripIDs mirrors registerFilePerms' 20 exact IDs.
// TestFilepermsRoundTripCoversEveryRegisteredID cross-checks this list
// against the registry mechanically, so a 21st rule does not go untested
// silently — the same check is what caught fileperms.compiler being absent
// from an earlier draft of this list.
//
// fileperms.compiler's production rule targets two absolute glob Patterns
// (/usr/bin/*-linux-gnu-as, /usr/bin/*-linux-gnu-ld.bfd) rather than one
// Path, which cannot resolve inside a temp dir. Like the other glob-backed
// IDs here (sudoers-dropins, cron, systemd-units, hostkey), the fixture
// substitutes a plain single path — glob expansion itself is
// fileperms_test.go's job, not this one's.
func filepermsRoundTripIDs() []string {
	return []string{
		"fileperms.shadow", "fileperms.passwd", "fileperms.group",
		"fileperms.sshd-config", "fileperms.hostkey", "fileperms.gshadow",
		"fileperms.sudoers", "fileperms.sudoers-dropins", "fileperms.cron",
		"fileperms.systemd-units", "fileperms.docker-config", "fileperms.grub-config",
		"fileperms.grub2-config", "fileperms.at-allow", "fileperms.at-deny",
		"fileperms.cron-allow", "fileperms.cron-deny", "fileperms.crontab",
		"fileperms.passwd-backup", "fileperms.compiler",
	}
}

func TestFilepermsRoundTripCoversEveryRegisteredID(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range fix.Default().Patterns() {
		if strings.HasPrefix(p, "fileperms.") {
			registered[p] = true
		}
	}
	covered := map[string]bool{}
	for _, id := range filepermsRoundTripIDs() {
		covered[id] = true
	}
	for id := range registered {
		if !covered[id] {
			t.Errorf("%s is registered but this file does not cover it — a rule was added without a fixture", id)
		}
	}
	for id := range covered {
		if !registered[id] {
			t.Errorf("%s is covered here but is not registered — this list has gone stale", id)
		}
	}
}

// All 19 registered IDs use buildTightenMode (ActionMode, not ActionEdit),
// so this uses applyFirstAlternativeMode rather than applyFirstAlternative.
//
// Each case is a single-rule fileperms.Checker over one temp file chmod'd to
// 0666, which is a superset of every registered MaxMode's r/w bits (none set
// execute) — so tighten() always lands exactly on MaxMode, and a single-rule
// checker means there is no second finding the "no other finding" direction
// could confuse with cross-contamination from a shared fixture. MaxMode
// itself comes from fileperms.DefaultRules(), the production table, rather
// than a copy held here.
func TestEveryFilePermsFixActuallyClearsTheFindingItClaimsToFix(t *testing.T) {
	maxModes := map[string]os.FileMode{}
	for _, r := range filepermscheck.DefaultRules() {
		maxModes[r.ID] = r.MaxMode
	}

	for _, id := range filepermsRoundTripIDs() {
		t.Run(id, func(t *testing.T) {
			maxMode, ok := maxModes[id]
			if !ok {
				t.Fatalf("%s is not in fileperms.DefaultRules()", id)
			}
			target := filepath.Join(t.TempDir(), "target")
			writeFixture(t, target, "x")
			if err := os.Chmod(target, 0o666); err != nil {
				t.Fatal(err)
			}
			checker := &filepermscheck.Checker{
				Rules: []filepermscheck.Rule{{
					Path: target, MaxMode: maxMode, Sev: model.SeverityMedium,
					ID: id, Title: "t", Desc: "d",
				}},
				OwnerUID: os.Getuid(),
			}

			before := runChecker(t, checker)
			f, ok := before[id]
			if !ok {
				t.Fatalf("the checker did not flag %s on a file chmod'd to 0666; it found %v", id, keysOf(before))
			}

			applyFirstAlternativeMode(t, f)
			after := runChecker(t, checker)
			if _, still := after[id]; still {
				fi, _ := os.Stat(target)
				t.Errorf("%s survived its own fix; file is now %#o, want %#o", id, fi.Mode().Perm(), maxMode)
			}
			if len(after) != 0 {
				t.Errorf("%s's fix left other findings standing on a single-rule checker: %v", id, keysOf(after))
			}
		})
	}
}
