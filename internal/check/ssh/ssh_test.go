package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// parseConfig parses a config from bytes with no Include resolution. The
// rule tests below care about which directives win, not about file layout;
// the Include tests use parseConfigFile against a real directory tree.
func parseConfig(data []byte) sshdConfig {
	p := &includeParser{
		cfg:     sshdConfig{values: map[string]string{}, origin: map[string]string{}},
		visited: map[string]bool{},
	}
	p.parse(data, "x", 0)
	return p.cfg
}

// writeTree writes files (relative path → content) under dir.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func idsOf(fs []model.Finding) map[string]model.Finding {
	m := map[string]model.Finding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestSSHRules(t *testing.T) {
	cfg := `# test sshd_config
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 10
X11Forwarding yes
`
	got := idsOf(auditConfig(parseConfig([]byte(cfg)), "/etc/ssh/sshd_config"))
	for _, want := range []string{"ssh.rootlogin", "ssh.passwordauth", "ssh.emptypasswords", "ssh.maxauthtries", "ssh.x11forwarding"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s", want)
		}
	}
	if got["ssh.emptypasswords"].Severity != model.SeverityCritical {
		t.Error("empty passwords should be critical")
	}
	for _, f := range got {
		if f.Validate() != nil {
			t.Errorf("invalid finding %s", f.ID)
		}
	}
}

func TestSSHHardenedConfigIsClean(t *testing.T) {
	cfg := `PermitRootLogin prohibit-password
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
`
	got := auditConfig(parseConfig([]byte(cfg)), "x")
	if len(got) != 0 {
		t.Errorf("hardened config produced findings: %v", got)
	}
}

func TestSSHDefaultsApply(t *testing.T) {
	// Empty config: sshd defaults mean PasswordAuthentication defaults to
	// yes (flagged) but PermitRootLogin defaults to prohibit-password (ok).
	got := idsOf(auditConfig(parseConfig(nil), "x"))
	if _, ok := got["ssh.rootlogin"]; ok {
		t.Error("default PermitRootLogin should not be flagged")
	}
	if _, ok := got["ssh.passwordauth"]; !ok {
		t.Error("default PasswordAuthentication (yes) should be flagged")
	}
}

func TestSSHStopsAtMatchBlock(t *testing.T) {
	cfg := `PasswordAuthentication no
Match User backup
    PasswordAuthentication yes
`
	got := idsOf(auditConfig(parseConfig([]byte(cfg)), "x"))
	if _, ok := got["ssh.passwordauth"]; ok {
		t.Error("top-level PasswordAuthentication no should win; Match block ignored")
	}
}

// TestIncludedFileWinsOverMainFile is the false-negative half of the
// Include bug: Debian and Ubuntu put the Include at the top of
// sshd_config, so a drop-in that loosens a setting beats the hardened line
// below it. Reading only the top-level file reports the host as clean.
func TestIncludedFileWinsOverMainFile(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config":               "Include sshd_config.d/*.conf\nPermitRootLogin no\n",
		"sshd_config.d/90-lax.conf": "PermitRootLogin yes\n",
	})
	main := filepath.Join(dir, "sshd_config")
	cfg, unread, err := parseConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(unread) != 0 {
		t.Errorf("unexpected unread files: %v", unread)
	}
	got := idsOf(auditConfig(cfg, main))
	f, ok := got["ssh.rootlogin"]
	if !ok {
		t.Fatal("PermitRootLogin yes in a drop-in should be flagged")
	}
	// The fix edits Evidence["config"]; pointing it at the main file would
	// write a directive the drop-in keeps overriding.
	want := filepath.Join(dir, "sshd_config.d/90-lax.conf")
	if f.Evidence["config"] != want {
		t.Errorf("finding points at %q, want the drop-in %q", f.Evidence["config"], want)
	}
}

// TestMainFileWinsWhenItComesFirst is the same mechanism in reverse: an
// Include below a directive cannot override it, because sshd keeps the
// first value it obtains.
func TestMainFileWinsWhenItComesFirst(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config":               "PermitRootLogin no\nInclude sshd_config.d/*.conf\n",
		"sshd_config.d/90-lax.conf": "PermitRootLogin yes\n",
	})
	main := filepath.Join(dir, "sshd_config")
	cfg, _, err := parseConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := idsOf(auditConfig(cfg, main))["ssh.rootlogin"]; ok {
		t.Error("an Include below the directive must not override it")
	}
}

// TestCloudImageDropInIsNotAFalsePositive is the false-positive half, and
// the one that hits nearly every cloud VPS: the image ships
// PasswordAuthentication no in a drop-in while the stock sshd_config below
// still says yes.
func TestCloudImageDropInIsNotAFalsePositive(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config": "Include sshd_config.d/*.conf\nPasswordAuthentication yes\n",
		"sshd_config.d/60-cloudimg-settings.conf": "PasswordAuthentication no\n",
	})
	main := filepath.Join(dir, "sshd_config")
	cfg, _, err := parseConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := idsOf(auditConfig(cfg, main))["ssh.passwordauth"]; ok {
		t.Error("password auth disabled by a drop-in must not be reported as enabled")
	}
}

// TestIncludeGlobOrderIsLexical pins the tie-break: sshd reads glob
// matches in sorted order, so the lower-numbered file wins.
func TestIncludeGlobOrderIsLexical(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config":           "Include conf.d/*.conf\n",
		"conf.d/10-first.conf":  "MaxAuthTries 3\n",
		"conf.d/20-second.conf": "MaxAuthTries 99\n",
	})
	main := filepath.Join(dir, "sshd_config")
	cfg, _, err := parseConfigFile(main)
	if err != nil {
		t.Fatal(err)
	}
	if got := effective(cfg, "MaxAuthTries", "6"); got != "3" {
		t.Errorf("MaxAuthTries = %q, want 3 from the lexically first file", got)
	}
}

func TestIncludeHandlesCyclesAndMissingGlobs(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config": "Include a.conf\nInclude empty.d/*.conf\n",
		"a.conf":      "Include sshd_config\nPermitEmptyPasswords yes\n",
	})
	main := filepath.Join(dir, "sshd_config")
	cfg, unread, err := parseConfigFile(main) // must terminate
	if err != nil {
		t.Fatal(err)
	}
	if len(unread) != 0 {
		t.Errorf("a glob matching nothing is normal, not unread: %v", unread)
	}
	if effective(cfg, "PermitEmptyPasswords", "no") != "yes" {
		t.Error("directives after a cyclic Include should still be parsed")
	}
}

// TestUnreadableIncludeIsPartial: a file we cannot read may contain a
// directive that overrides anything we did read, so the domain is Degraded
// rather than reported as a complete audit.
func TestUnreadableIncludeIsPartial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 files")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"sshd_config":           "Include conf.d/*.conf\nPermitRootLogin yes\n",
		"conf.d/50-secret.conf": "PermitRootLogin no\n",
	})
	secret := filepath.Join(dir, "conf.d/50-secret.conf")
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatal(err)
	}

	c := &Checker{ConfigPath: filepath.Join(dir, "sshd_config")}
	fs, err := c.Check(context.Background(), platform.Env{})
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError, got %v", err)
	}
	if partial.Covered >= partial.Total {
		t.Errorf("coverage %d/%d does not report a gap", partial.Covered, partial.Total)
	}
	// Findings are kept: PartialError means incomplete, not failed.
	if _, ok := idsOf(fs)["ssh.rootlogin"]; !ok {
		t.Error("a partial audit should still return the findings it did derive")
	}
}

func TestSSHAvailability(t *testing.T) {
	dir := t.TempDir()
	c := &Checker{ConfigPath: filepath.Join(dir, "missing")}
	if ok, _ := c.Available(context.Background(), platform.Env{}); ok {
		t.Error("Available should be false when sshd_config is missing")
	}
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PermitRootLogin yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.ConfigPath = path
	if ok, _ := c.Available(context.Background(), platform.Env{}); !ok {
		t.Error("Available should be true when sshd_config exists")
	}
	fs, err := c.Check(context.Background(), platform.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := idsOf(fs)["ssh.rootlogin"]; !ok {
		t.Error("Check should flag root login from the real file")
	}
}
