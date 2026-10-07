package accounts

import (
	"context"
	"testing"
	"time"
)

// A UID-0 account that is locked and expired can no longer authenticate by
// any route, which is the state the uid0 fix leaves behind. Each half alone
// is not that state: a locked password still admits an SSH key, and an
// expired account with a live password is one chage away from working.
func TestADisabledUID0AccountIsNoLongerReported(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd+"backdoor:x:0:0::/root:/bin/bash\n")
	for _, tc := range []struct {
		name, shadow string
		reported     bool
	}{
		{"locked and expired", "backdoor:!$6$x:19000:0:99999:7::1:\n", false},
		{"locked only", "backdoor:!$6$x:19000:0:99999:7:::\n", true},
		{"expired only", "backdoor:$6$x:19000:0:99999:7::1:\n", true},
		{"expiring in the future", "backdoor:!$6$x:19000:0:99999:7::999999:\n", true},
	} {
		sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\n"+tc.shadow)
		fs, err := (&Checker{PasswdPath: pw, ShadowPath: sh}).Check(context.Background(), noSudo())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := has(fs, "accounts.uid0"); got != tc.reported {
			t.Errorf("%s: uid0 reported = %v, want %v", tc.name, got, tc.reported)
		}
	}
}

// Without /etc/shadow nothing can be known about lock state, so every UID-0
// account is reported, exactly as before shadow was consulted.
func TestUID0IsStillReportedWhenShadowIsUnreadable(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd+"backdoor:x:0:0::/root:/bin/bash\n")
	fs, _ := (&Checker{PasswdPath: pw, ShadowPath: "/nonexistent/shadow"}).Check(context.Background(), noSudo())
	if !has(fs, "accounts.uid0") {
		t.Fatalf("uid0 must be reported when shadow cannot be read, got %v", fs)
	}
}

func TestDisabledAccountsReadsTheExpiryAsDays(t *testing.T) {
	now := time.Unix(20000*86400, 0)
	disabled := disabledAccounts([]byte("a:!x:1:0:1:1::20000:\nb:!x:1:0:1:1::20001:\nc:!x:1:0:1:1:::\n"), now)
	for name, want := range map[string]bool{"a": true, "b": false, "c": false, "missing": false} {
		if got := disabled(name); got != want {
			t.Errorf("%s disabled = %v, want %v", name, got, want)
		}
	}
}
