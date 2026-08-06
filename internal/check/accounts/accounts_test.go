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
			if f.Severity != model.SeverityHigh {
				t.Errorf("uid0 severity = %v, want high", f.Severity)
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

// A service account with an empty password field but no way to log in is
// not "a login account with an empty password", and reporting it as one is
// a false Critical that also drags the account-hygiene axis down.
//
// This used to depend on where the distribution keeps nologin. The shell
// was matched against a fixed list of six full paths, so Debian and Fedora
// were recognised and Arch (/usr/bin/nologin) and NixOS (under
// /run/current-system/sw/bin) were not — on those hosts every such account
// was read as an ordinary login.
func TestEmptyPasswordIgnoresNonLoginShellsAtAnyPath(t *testing.T) {
	for _, shell := range []string{
		"/usr/sbin/nologin",                  // Debian, Ubuntu
		"/sbin/nologin",                      // RHEL, Fedora
		"/usr/bin/nologin",                   // Arch
		"/run/current-system/sw/bin/nologin", // NixOS
		"/usr/local/sbin/nologin",            // hand-built
		"/bin/false",
		"/bin/true",
		"", // no shell recorded at all
	} {
		t.Run(shell, func(t *testing.T) {
			pw := writeFile(t, "passwd", cleanPasswd+"svc:x:998:998::/var/lib/svc:"+shell+"\n")
			sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nsvc::19000:0:99999:7:::\n")
			c := &Checker{PasswdPath: pw, ShadowPath: sh}
			fs, err := c.Check(context.Background(), platform.Env{})
			if err != nil {
				t.Fatal(err)
			}
			if has(fs, "accounts.emptypassword") {
				t.Errorf("shell %q cannot log in, but the account was reported as an empty-password login", shell)
			}
		})
	}
}

// The other direction, which matters just as much: widening what counts as
// a non-login shell must not stop the finding firing on a real login.
func TestEmptyPasswordStillFiresOnARealLoginShell(t *testing.T) {
	for _, shell := range []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh", "/bin/falsehood"} {
		t.Run(shell, func(t *testing.T) {
			pw := writeFile(t, "passwd", cleanPasswd+"weak:x:1001:1001::/home/weak:"+shell+"\n")
			sh := writeFile(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nweak::19000:0:99999:7:::\n")
			c := &Checker{PasswdPath: pw, ShadowPath: sh}
			fs, err := c.Check(context.Background(), platform.Env{})
			if err != nil {
				t.Fatal(err)
			}
			if !has(fs, "accounts.emptypassword") {
				t.Errorf("shell %q is a real login shell with an empty password and must be reported", shell)
			}
		})
	}
}
