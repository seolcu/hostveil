package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/platform"
)

type fakeRunner struct {
	present map[string]bool
	outputs map[string]string // key: "name arg1 arg2..."
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.present[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if out, ok := f.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no output for: " + key)
}

func check(t *testing.T, r fakeRunner) int {
	t.Helper()
	fs, err := New().Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	return len(fs)
}

func TestFirewallActiveUFW(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"ufw": true},
		outputs: map[string]string{"ufw status": "Status: active\n"},
	}
	if n := check(t, r); n != 0 {
		t.Errorf("active ufw should yield no finding, got %d", n)
	}
}

func TestFirewallInactive(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"ufw": true},
		outputs: map[string]string{"ufw status": "Status: inactive\n"},
	}
	if n := check(t, r); n != 1 {
		t.Errorf("inactive ufw should yield one finding, got %d", n)
	}
}

func TestFirewallNoneInstalled(t *testing.T) {
	r := fakeRunner{present: map[string]bool{}}
	if n := check(t, r); n != 1 {
		t.Errorf("no firewall installed should yield one finding, got %d", n)
	}
}

func TestFirewallFirewalld(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"firewall-cmd": true},
		outputs: map[string]string{"firewall-cmd --state": "running\n"},
	}
	if n := check(t, r); n != 0 {
		t.Errorf("running firewalld should yield no finding, got %d", n)
	}
}

func TestFirewallNftablesActive(t *testing.T) {
	// A real host firewall: an input base chain that drops by default.
	ruleset := `table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
	}
}`
	r := fakeRunner{
		present: map[string]bool{"nft": true},
		outputs: map[string]string{"nft list ruleset": ruleset},
	}
	if n := check(t, r); n != 0 {
		t.Errorf("an active input-dropping nftables firewall should yield no finding, got %d", n)
	}
}

// TestFirewallDockerRulesNotCountedAsFirewall is the regression guard for
// the false-negative found by the demo VM: Docker installs nftables tables
// for container networking, but they are NOT a host firewall, so a Docker
// host with no ufw/firewalld must still be flagged.
func TestFirewallDockerRulesNotCountedAsFirewall(t *testing.T) {
	dockerRuleset := `table ip nat {
	chain DOCKER { }
	chain POSTROUTING { type nat hook postrouting priority srcnat; policy accept; }
}
table ip filter {
	chain DOCKER { }
	chain FORWARD { type filter hook forward priority filter; policy accept; }
}`
	r := fakeRunner{
		present: map[string]bool{"nft": true},
		outputs: map[string]string{"nft list ruleset": dockerRuleset},
	}
	if n := check(t, r); n != 1 {
		t.Errorf("Docker's nftables tables must not count as a firewall; expected 1 finding, got %d", n)
	}
}
