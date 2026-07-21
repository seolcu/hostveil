package firewall

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

// dockerHost builds a runner for a host with ufw active and Docker reachable.
// Callers override or add entries to shape the specific scenario.
func dockerHost(ps, dockerUser string) fakeRunner {
	return fakeRunner{
		present: map[string]bool{"ufw": true, "iptables": true, "docker": true},
		outputs: map[string]string{
			"ufw status": "Status: active\n",
			"docker version --format {{.Server.Version}}": "27.3.1\n",
			"docker ps --format {{.Names}}\t{{.Ports}}":   ps,
			"iptables -S DOCKER-USER":                     dockerUser,
		},
	}
}

// emptyDockerUser is what Docker installs by default: the chain exists and
// unconditionally returns, so it filters nothing.
const emptyDockerUser = "-N DOCKER-USER\n-A DOCKER-USER -j RETURN\n"

func checkWith(t *testing.T, r fakeRunner) ([]model.Finding, error) {
	t.Helper()
	c := &Checker{DaemonConfigPath: filepath.Join(t.TempDir(), "absent.json")}
	return c.Check(context.Background(), platform.Env{Runner: r})
}

// The headline case: ufw reports active, so every axis scored this host
// clean, while Redis and Postgres were reachable from the internet.
func TestPublishedPortsBypassingUFWAreCritical(t *testing.T) {
	r := dockerHost("cache\t0.0.0.0:6379->6379/tcp, :::6379->6379/tcp\ndb\t0.0.0.0:5432->5432/tcp\n", emptyDockerUser)

	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d (%v)", len(fs), fs)
	}
	f := fs[0]
	if f.ID != "firewall.docker-bypass" {
		t.Errorf("id = %q", f.ID)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	// Both containers listed, IPv4+IPv6 of the same port collapsed to one,
	// and ordered by port so repeat scans produce no spurious delta.
	if got, want := f.Evidence["published"], "5432 (db), 6379 (cache)"; got != want {
		t.Errorf("published = %q, want %q", got, want)
	}
}

// Loopback publishing is the recommended remediation, so it must never be
// reported as the problem it solves.
func TestLoopbackPublishedPortIsNotABypass(t *testing.T) {
	r := dockerHost("cache\t127.0.0.1:6379->6379/tcp\n", emptyDockerUser)

	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("loopback-published port is not exposed, got %v", fs)
	}
}

// A container with no published ports at all.
func TestUnpublishedPortIsNotABypass(t *testing.T) {
	r := dockerHost("cache\t6379/tcp\n", emptyDockerUser)

	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("an unpublished container port is not exposed, got %v", fs)
	}
}

// An operator who already installed the ufw-docker rules has fixed this.
// Flagging them would be the false positive that discredits the finding.
func TestFilteredDockerUserChainSuppressesTheFinding(t *testing.T) {
	filtered := "-N DOCKER-USER\n-A DOCKER-USER -s 10.0.0.0/8 -j RETURN\n-A DOCKER-USER -j DROP\n"
	r := dockerHost("cache\t0.0.0.0:6379->6379/tcp\n", filtered)

	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a filtered DOCKER-USER chain means the bypass is closed, got %v", fs)
	}
}

// With "iptables": false Docker writes no rules, so ufw governs normally.
func TestDockerNotManagingIptablesSuppressesTheFinding(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(cfg, []byte(`{"iptables": false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := dockerHost("cache\t0.0.0.0:6379->6379/tcp\n", emptyDockerUser)

	c := &Checker{DaemonConfigPath: cfg}
	fs, err := c.Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("Docker is not managing iptables, so ufw applies; got %v", fs)
	}
}

// The inverse: an explicit "iptables": true, and any other daemon.json
// content, leaves the check armed.
func TestDaemonConfigWithoutIptablesKeyStillFlags(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(cfg, []byte(`{"log-driver": "json-file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := dockerHost("cache\t0.0.0.0:6379->6379/tcp\n", emptyDockerUser)

	c := &Checker{DaemonConfigPath: cfg}
	fs, err := c.Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Errorf("an unrelated daemon.json must not disarm the check, got %v", fs)
	}
}

// No Docker means no Docker rules to jump the queue.
func TestNoDockerNoBypass(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"ufw": true},
		outputs: map[string]string{"ufw status": "Status: active\n"},
	}
	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("no Docker, no bypass; got %v", fs)
	}
}

// The finding names ufw and its remediation edits /etc/ufw/after.rules, so
// it must not fire on a firewalld host where neither applies.
func TestBypassScopedToUFW(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"firewall-cmd": true, "iptables": true, "docker": true},
		outputs: map[string]string{
			"firewall-cmd --state":                        "running\n",
			"docker version --format {{.Server.Version}}": "27.3.1\n",
			"docker ps --format {{.Names}}\t{{.Ports}}":   "cache\t0.0.0.0:6379->6379/tcp\n",
			"iptables -S DOCKER-USER":                     emptyDockerUser,
		},
	}
	fs, err := checkWith(t, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("the ufw-docker finding must not fire on firewalld, got %v", fs)
	}
}

// Whether the operator already closed the bypass is the one thing that
// cannot be guessed. Unreadable means say so, not assume either answer:
// assuming closed hides a Critical exposure, assuming open accuses a host
// that may be correctly configured.
func TestUnreadableDockerUserChainIsPartial(t *testing.T) {
	r := dockerHost("cache\t0.0.0.0:6379->6379/tcp\n", "")
	delete(r.outputs, "iptables -S DOCKER-USER") // no scripted output -> Run errors

	fs, err := checkWith(t, r)
	if len(fs) != 0 {
		t.Errorf("must not invent a finding from unread evidence, got %v", fs)
	}
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
}
