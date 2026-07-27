package agent

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The paths this checker reads live inside other people's home directories,
// and it reads them as root. Everything here is one account arranging its own
// home so that a routine audit does something on its behalf.

// The worst of the three: a symlink where the config file should be, pointing
// at a file the attacker does not own. Following it would let any user collect
// an agent.config-perms finding *about /etc/passwd* — carrying an Auto chmod
// fix — and have `fix --all` tighten the password database to 0600, which
// breaks logins, sudo, and every getpwnam on the host.
func TestSymlinkedConfigProducesNoModeFinding(t *testing.T) {
	h := newHost(t, "mallory")
	victim := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(victim, []byte("root:x:0:0::/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(h.homes["mallory"], ".openclaw", "openclaw.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	fs, _ := h.checker().Check(context.Background(), envNoFirewall(""))
	for _, f := range fs {
		if f.ID == "agent.config-perms" || f.ID == "agent.secret-exposed" {
			t.Fatalf("a symlinked config produced %s with evidence %v — "+
				"root would chmod %s on the strength of it", f.ID, f.Evidence, victim)
		}
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o644 {
		t.Errorf("the checker changed the link target's mode to %#o", fi.Mode().Perm())
	}
}

// Same trick against the credentials path, which is the Secret rule and the
// higher-severity finding. Reading through the link would also mean parsing
// the victim's contents looking for API keys.
func TestSymlinkedSecretFileProducesNoFinding(t *testing.T) {
	h := newHost(t, "mallory")
	victim := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(victim, []byte("API_KEY=sk-not-really-a-key-but-literal\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(h.homes["mallory"], ".hermes", ".env")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	fs, _ := h.checker().Check(context.Background(), envNoFirewall(""))
	for _, f := range fs {
		if f.ID == "agent.secret-exposed" {
			t.Fatalf("a symlinked secret file produced %s: %v", f.ID, f.Evidence)
		}
	}
}

// A FIFO in place of a config file used to park the scan inside open(2)
// forever: it blocks until a writer appears, and the attacker simply never
// writes. There is no timeout on a file read, so the whole scan hangs.
func TestFIFOConfigDoesNotHangTheScan(t *testing.T) {
	h := newHost(t, "mallory")
	p := filepath.Join(h.homes["mallory"], ".openclaw", "openclaw.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = h.checker().Check(context.Background(), envNoFirewall(""))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Check blocked on a FIFO left where a config file should be")
	}
}

// A symlink to /dev/zero reads forever and allocates while it does. The size
// cap turns it into an ordinary unreadable-config degradation.
func TestUnboundedDeviceConfigIsBounded(t *testing.T) {
	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("no /dev/zero")
	}
	h := newHost(t, "mallory")
	p := filepath.Join(h.homes["mallory"], ".openclaw", "openclaw.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", p); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = h.checker().Check(context.Background(), envNoFirewall(""))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Check did not bound a read of /dev/zero")
	}
}

// The defence must not cost the ordinary case. A real config, read normally,
// still yields its findings.
func TestARealConfigIsStillRead(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o644)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if _, ok := findByID(fs, "agent.config-perms"); !ok {
		t.Error("a genuinely world-readable config must still be reported")
	}
}
