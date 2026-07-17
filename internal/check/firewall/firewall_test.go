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

func TestFirewallNftables(t *testing.T) {
	r := fakeRunner{
		present: map[string]bool{"nft": true},
		outputs: map[string]string{"nft list ruleset": "table inet filter {\n  chain input {\n  }\n}\n"},
	}
	if n := check(t, r); n != 0 {
		t.Errorf("nftables with a table should yield no finding, got %d", n)
	}
}
