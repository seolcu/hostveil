package fix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	accountscheck "github.com/seolcu/hostveil/internal/check/accounts"
)

// Six of accounts' findings edit a file the checker reads back directly
// (login.defs, limits.conf, the two banners), which makes them roundtrip
// candidates the same way ssh's are. accounts.emptypassword is excluded: its
// registered fix is `passwd -l` (ActionExec), which applyFirstAlternative
// already refuses.
//
// One fixture trips all six at once, mirroring sshdBad's design: it is what
// proves fixing one does not disturb the other five.
func accountsRoundTripCases() []roundTrip {
	setup := func(t *testing.T, dir string) check.Checker {
		t.Helper()
		loginDefs := filepath.Join(dir, "login.defs")
		limits := filepath.Join(dir, "limits.conf")
		issue := filepath.Join(dir, "issue")
		issueNet := filepath.Join(dir, "issue.net")
		passwd := filepath.Join(dir, "passwd")
		shadow := filepath.Join(dir, "shadow")

		writeFixture(t, loginDefs, "SHA_CRYPT_MIN_ROUNDS 1000\nSHA_CRYPT_MAX_ROUNDS 1000\nUMASK 022\nPASS_MIN_DAYS 0\nPASS_MAX_DAYS 99999\n")
		writeFixture(t, limits, "# no core-dump limit set\n")
		writeFixture(t, issue, "Welcome\n")
		writeFixture(t, issueNet, "Welcome\n")
		// A minimal, well-formed passwd/shadow pair with no login accounts, so
		// accounts.uid0/duplicate-uid/emptypassword/sudo-nopasswd never fire
		// and the six IDs under test are the only findings in play.
		writeFixture(t, passwd, "root:x:0:0:root:/root:/bin/bash\n")
		writeFixture(t, shadow, "root:!:19000:0:99999:7:::\n")

		return &accountscheck.Checker{
			PasswdPath:    passwd,
			ShadowPath:    shadow,
			LoginDefsPath: loginDefs,
			LimitsPath:    limits,
			IssuePath:     issue,
			IssueNetPath:  issueNet,
		}
	}
	ids := []string{
		"accounts.password-rounds", "accounts.default-umask", "accounts.password-aging",
		"accounts.core-dumps", "accounts.local-banner", "accounts.remote-banner",
	}
	out := make([]roundTrip, 0, len(ids))
	for _, id := range ids {
		out = append(out, roundTrip{want: id, setup: setup})
	}
	return out
}

func TestEveryAccountsFixActuallyClearsTheFindingItClaimsToFix(t *testing.T) {
	for _, tc := range accountsRoundTripCases() {
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

func TestAnAccountsFixClearsItsOwnFindingAndNoOther(t *testing.T) {
	for _, tc := range accountsRoundTripCases() {
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
				t.Errorf("fixing %s introduced %s, which was not there before", tc.want, id)
			}
		})
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}
