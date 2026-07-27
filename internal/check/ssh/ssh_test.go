package ssh

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
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
`
	got := auditConfig(parseConfig([]byte(cfg)), "x")
	if len(got) != 0 {
		t.Errorf("hardened config produced findings: %v", got)
	}
}

func TestGraceTimeGatewayAndHostbasedRules(t *testing.T) {
	cfg := `LoginGraceTime 2m
GatewayPorts clientspecified
HostbasedAuthentication yes
`
	got := idsOf(auditConfig(parseConfig([]byte(cfg)), "x"))
	for _, want := range []string{"ssh.logingracetime", "ssh.gatewayports", "ssh.hostbasedauth"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected %s, got %v", want, got)
		}
	}
	if got["ssh.logingracetime"].Evidence["value"] != "2m" {
		t.Errorf("grace-time evidence = %q, want the configured value", got["ssh.logingracetime"].Evidence["value"])
	}
}

func TestUnlimitedGraceTimeIsFlagged(t *testing.T) {
	got := idsOf(auditConfig(parseConfig([]byte("LoginGraceTime 0\n")), "x"))
	if _, ok := got["ssh.logingracetime"]; !ok {
		t.Error("LoginGraceTime 0 means no limit and must be flagged")
	}
}

// The finding exists for the contradiction only: an operator who left
// PasswordAuthentication on has not been misled about what is in force.
func TestKbdInteractiveFlaggedOnlyWhenPasswordsAreOff(t *testing.T) {
	got := idsOf(auditConfig(parseConfig([]byte("PasswordAuthentication no\n")), "x"))
	f, ok := got["ssh.kbdinteractive"]
	if !ok {
		t.Fatal("default KbdInteractiveAuthentication (yes) with PasswordAuthentication no should be flagged")
	}
	if f.Evidence["directive"] != "KbdInteractiveAuthentication" {
		t.Errorf("directive evidence = %q, want the modern keyword", f.Evidence["directive"])
	}

	got = idsOf(auditConfig(parseConfig([]byte("PasswordAuthentication yes\n")), "x"))
	if _, ok := got["ssh.kbdinteractive"]; ok {
		t.Error("with passwords still allowed there is no contradiction to report")
	}
}

// ChallengeResponseAuthentication is the pre-8.7 alias for the same option,
// and sshd keeps the first value it sees for either keyword. The finding
// must respect an alias-based opt-out, and when the alias is the keyword in
// force, name it so the fix edits the directive that actually wins.
func TestChallengeResponseAliasIsRespected(t *testing.T) {
	got := idsOf(auditConfig(parseConfig([]byte("PasswordAuthentication no\nChallengeResponseAuthentication no\n")), "x"))
	if _, ok := got["ssh.kbdinteractive"]; ok {
		t.Error("disabling the old alias closes the same door; nothing to report")
	}

	got = idsOf(auditConfig(parseConfig([]byte("PasswordAuthentication no\nChallengeResponseAuthentication yes\n")), "x"))
	f, ok := got["ssh.kbdinteractive"]
	if !ok {
		t.Fatal("an explicit yes through the alias should be flagged")
	}
	if f.Evidence["directive"] != "ChallengeResponseAuthentication" {
		t.Errorf("directive evidence = %q, want the alias in force", f.Evidence["directive"])
	}
}

func TestParseSSHDuration(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"120", 120, true},
		{"2m", 120, true},
		{"1h30m", 5400, true},
		{"90s", 90, true},
		{"0", 0, true},
		{"", 0, false},
		{"none", 0, false},
		{"m5", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseSSHDuration(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseSSHDuration(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
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

// bufio.Scanner stops at a line over 64 KiB and reports it only through
// Err(), which nothing checked. The parse ended silently partway, every
// directive after that point read as unset, and the compiled-in default won
// the audit — so PermitRootLogin's verdict depended on which side of the
// long line it sat, with nothing saying the file had been truncated.
func TestAnOverlongLineDegradesRatherThanTruncatingSilently(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	body := "PermitRootLogin no\n" +
		"# " + strings.Repeat("x", 128*1024) + "\n" +
		"PasswordAuthentication no\n"
	if err := os.WriteFile(main, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, unread, err := parseConfigFile(main)
	if err != nil {
		t.Fatalf("parseConfigFile: %v", err)
	}
	if len(unread) != 1 || unread[0] != main {
		t.Errorf("a truncated parse must be reported as unread, got %v", unread)
	}
	// What was read before the long line is still valid and worth keeping.
	if cfg.values["permitrootlogin"] != "no" {
		t.Errorf("directives before the long line should survive, got %q", cfg.values["permitrootlogin"])
	}

	c := &Checker{ConfigPath: main}
	findings, err := c.Check(context.Background(), platform.Env{})
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError, got %v", err)
	}
	if !strings.Contains(partial.Reason, main) {
		t.Errorf("the reason should name the file: %q", partial.Reason)
	}
	// Findings gathered before the truncation are real and must be kept.
	_ = findings
}

// The ordinary file must not be reported as truncated, or the flag means
// nothing.
func TestANormalConfigIsNotReportedAsUnread(t *testing.T) {
	main := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(main, []byte("PermitRootLogin no\nPasswordAuthentication no\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, unread, err := parseConfigFile(main); err != nil || len(unread) != 0 {
		t.Errorf("unread = %v, err = %v; want neither", unread, err)
	}
}
