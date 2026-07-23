package accounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func has(fs []model.Finding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}

const cleanPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`

func TestCleanAccountsNoFindings(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd)
	sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nalice:$6$def:19000:0:99999:7:::\n")
	c := &Checker{PasswdPath: pw, ShadowPath: sh}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("clean host should have no findings, got %v", fs)
	}
}

func TestRogueUID0(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd+"backdoor:x:0:0::/root:/bin/bash\n")
	sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\n")
	c := &Checker{PasswdPath: pw, ShadowPath: sh}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !has(fs, "accounts.uid0") {
		t.Fatalf("expected accounts.uid0, got %v", fs)
	}
	for _, f := range fs {
		if f.ID == "accounts.uid0" {
			if f.Severity != model.SeverityCritical {
				t.Errorf("uid0 severity = %v, want critical", f.Severity)
			}
			if f.Evidence["accounts"] != "backdoor" {
				t.Errorf("evidence = %v", f.Evidence)
			}
		}
	}
}

func TestRogueUID0LeadingZero(t *testing.T) {
	// The kernel parses "00" as UID 0, so a leading-zero backdoor must still
	// be caught — a naive string compare against "0" would miss it.
	pw := writeFile(t, "passwd", cleanPasswd+"backdoor:x:00:0::/root:/bin/bash\n")
	sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\n")
	c := &Checker{PasswdPath: pw, ShadowPath: sh}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !has(fs, "accounts.uid0") {
		t.Fatalf("leading-zero UID-0 account must be flagged, got %v", fs)
	}
}

func TestEmptyPasswordLoginAccount(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd)
	// alice has an empty password field and a login shell -> flagged.
	sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nalice::19000:0:99999:7:::\n")
	c := &Checker{PasswdPath: pw, ShadowPath: sh}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if !has(fs, "accounts.emptypassword") {
		t.Fatalf("expected accounts.emptypassword, got %v", fs)
	}
}

func TestEmptyPasswordOnNonLoginAccountIgnored(t *testing.T) {
	// daemon has an empty password but a nologin shell -> not a login risk.
	pw := writeFile(t, "passwd", cleanPasswd)
	sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\ndaemon::19000:0:99999:7:::\n")
	c := &Checker{PasswdPath: pw, ShadowPath: sh}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "accounts.emptypassword") {
		t.Errorf("empty password on a nologin account should be ignored, got %v", fs)
	}
}

// An unreadable /etc/shadow costs the empty-password half of this domain.
// The findings from the readable half are still real and must survive, but
// the result must say so: reporting clean would score identically to "every
// account has a password" while meaning "nobody looked", and the axis would
// hand a non-root scan full marks for account hygiene it never checked.
func TestShadowUnreadableIsPartialNotClean(t *testing.T) {
	pw := writeFile(t, "passwd", cleanPasswd+"backdoor:x:0:0::/root:/bin/bash\n")
	c := &Checker{PasswdPath: pw, ShadowPath: filepath.Join(t.TempDir(), "missing-shadow")}
	fs, err := c.Check(context.Background(), platform.Env{})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("unreadable shadow must yield a PartialError (→ Degraded), got %v", err)
	}
	if !strings.Contains(partial.Reason, "empty password") {
		t.Errorf("reason should name what went unchecked, got %q", partial.Reason)
	}
	if !has(fs, "accounts.uid0") {
		t.Errorf("uid0 check should still run when shadow is unreadable, got %v", fs)
	}
}

func TestUnavailableWithoutPasswd(t *testing.T) {
	c := &Checker{PasswdPath: filepath.Join(t.TempDir(), "nope"), ShadowPath: "/etc/shadow"}
	if ok, _ := c.Available(context.Background(), platform.Env{}); ok {
		t.Error("checker should be unavailable when passwd is unreadable")
	}
}
