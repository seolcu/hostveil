package ssh

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

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
