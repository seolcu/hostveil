package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
)

// fail2banLoadStateArgv is the exact command fail2banInstalled runs.
var fail2banLoadStateArgv = []string{"systemctl", "show", "fail2ban.service", "--property=LoadState"}

func scriptFail2ban(r *checktest.Runner, loaded bool) *checktest.Runner {
	state := "LoadState=not-found\n"
	if loaded {
		state = "LoadState=loaded\n"
	}
	return r.Script(state, fail2banLoadStateArgv...)
}

func TestScanJailFindingFiresWhenFail2banInstalledButJailIsOff(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "user www-data;\n"})
	c := &Checker{NginxRoot: root, Fail2banConfDir: filepath.Join(t.TempDir(), "no-fail2ban-config")}
	env := scriptFail2ban(checktest.New().Without("docker"), true).Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("nothing went unexamined here: %v", err)
	}
	if has(fs, "proxy.no-scan-jail") == nil {
		t.Fatalf("expected proxy.no-scan-jail, got %v", fs)
	}
}

func TestScanJailFindingSilentWhenFail2banNotInstalled(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "user www-data;\n"})
	c := &Checker{NginxRoot: root}
	env := scriptFail2ban(checktest.New().Without("docker"), false).Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("fail2ban not being installed is a real answer, not a gap: %v", err)
	}
	if f := has(fs, "proxy.no-scan-jail"); f != nil {
		t.Errorf("updates.fail2ban already covers this host; proxy should stay silent, got %v", f)
	}
}

func TestScanJailFindingSilentWhenJailAlreadyEnabled(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "user www-data;\n"})
	f2bDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(f2bDir, "jail.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[nginx-http-auth]\nenabled = false\n\n[nginx-botsearch]\nenabled = true\nmaxretry = 2\n"
	if err := os.WriteFile(filepath.Join(f2bDir, "jail.d", "hostveil-nginx-scan.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Checker{NginxRoot: root, Fail2banConfDir: f2bDir}
	env := scriptFail2ban(checktest.New().Without("docker"), true).Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("nothing went unexamined here: %v", err)
	}
	if f := has(fs, "proxy.no-scan-jail"); f != nil {
		t.Errorf("the jail is already on, got %v", f)
	}
}

func TestScanJailCoverageDegradesWhenFail2banStateUnknown(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "user www-data;\n"})
	c := &Checker{NginxRoot: root}
	// systemctl left unscripted: the fake host cannot answer, which must not
	// be read as "fail2ban is not installed".
	env := checktest.New().Without("docker").Env()

	_, err := c.Check(context.Background(), env)
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("an unanswered systemctl probe must degrade the domain, got %v", err)
	}
	if !contains(partial.Reason, "fail2ban") {
		t.Errorf("the reason must name what could not be determined, got %q", partial.Reason)
	}
}

func TestScanJailCoverageDegradesWhenJailDirUnreadable(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "user www-data;\n"})
	f2bDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(f2bDir, "jail.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(f2bDir, "jail.d", "hostveil-nginx-scan.conf")
	if err := os.WriteFile(secret, []byte("[nginx-botsearch]\nenabled = true\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files, so the gap cannot be staged")
	}

	c := &Checker{NginxRoot: root, Fail2banConfDir: f2bDir}
	env := scriptFail2ban(checktest.New().Without("docker"), true).Env()

	_, err := c.Check(context.Background(), env)
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("an unreadable jail.d file must degrade the domain, got %v", err)
	}
	if !contains(partial.Reason, "hostveil-nginx-scan.conf") {
		t.Errorf("the reason must name what went unread, got %q", partial.Reason)
	}
}

func TestScanJailEvidenceNamesACustomErrorLog(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf": "user www-data;\nerror_log /srv/logs/nginx-error.log;\n",
	})
	c := &Checker{NginxRoot: root, Fail2banConfDir: filepath.Join(t.TempDir(), "no-fail2ban-config")}
	env := scriptFail2ban(checktest.New().Without("docker"), true).Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("nothing went unexamined here: %v", err)
	}
	f := has(fs, "proxy.no-scan-jail")
	if f == nil {
		t.Fatalf("expected proxy.no-scan-jail, got %v", fs)
	}
	if f.Evidence["error-log"] != "/srv/logs/nginx-error.log" {
		t.Errorf("error-log evidence = %q, want the custom path so the fix can override logpath",
			f.Evidence["error-log"])
	}
}

func TestScanJailEvidenceOmittedForTheDefaultErrorLog(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf": "user www-data;\nerror_log /var/log/nginx/error.log;\n",
	})
	c := &Checker{NginxRoot: root, Fail2banConfDir: filepath.Join(t.TempDir(), "no-fail2ban-config")}
	env := scriptFail2ban(checktest.New().Without("docker"), true).Env()

	fs, err := c.Check(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	f := has(fs, "proxy.no-scan-jail")
	if f == nil {
		t.Fatalf("expected proxy.no-scan-jail, got %v", fs)
	}
	// Evidence is still recorded — only the fix decides not to act on a
	// value equal to the compiled-in default.
	if f.Evidence["error-log"] != "/var/log/nginx/error.log" {
		t.Errorf("error-log evidence = %q", f.Evidence["error-log"])
	}
}
