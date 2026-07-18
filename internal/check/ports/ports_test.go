package ports

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// fakeRunner scripts `ss` output and simulates which binaries are present.
type fakeRunner struct {
	ss      string
	missing map[string]bool // binaries reported as absent
	outputs map[string]string
}

func (f fakeRunner) LookPath(name string) (string, error) {
	if f.missing[name] {
		return "", errors.New("not found: " + name)
	}
	return "/usr/bin/" + name, nil
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name == "ss" {
		return []byte(f.ss), nil
	}
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if out, ok := f.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no output for: " + key)
}

func findByID(fs []model.Finding, id string) (model.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func TestUnavailableWithoutSS(t *testing.T) {
	c := New()
	ok, reason := c.Available(context.Background(), platform.Env{Runner: fakeRunner{missing: map[string]bool{"ss": true}}})
	if ok {
		t.Fatal("ports checker should be unavailable without ss")
	}
	if reason == "" {
		t.Error("expected a skip reason")
	}
}

func TestExposedDatastoreFlagged(t *testing.T) {
	ss := `LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=999,fd=6))
LISTEN 0 128 [::]:6379 [::]:* users:(("redis-server",pid=999,fd=7))`
	fs, err := New().Check(context.Background(), platform.Env{Runner: fakeRunner{ss: ss}})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "ports.exposed-datastore")
	if !ok {
		t.Fatalf("expected ports.exposed-datastore, got %v", fs)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.Evidence["port"] != "6379" || f.Evidence["process"] != "redis-server" {
		t.Errorf("evidence = %v", f.Evidence)
	}
	// v4 + v6 rows for the same port must yield exactly one finding.
	count := 0
	for _, x := range fs {
		if x.ID == "ports.exposed-datastore" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 datastore finding across v4+v6, got %d", count)
	}
}

func TestTwoDistinctDatastoresBothCounted(t *testing.T) {
	ss := `LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1,fd=6))
LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2,fd=5))`
	fs, err := New().Check(context.Background(), platform.Env{Runner: fakeRunner{ss: ss}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	count := 0
	for _, f := range fs {
		if f.ID == "ports.exposed-datastore" {
			count++
			if seen[f.Key()] {
				t.Errorf("two datastores collapsed to the same Key %q", f.Key())
			}
			seen[f.Key()] = true
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 distinct datastore findings, got %d (%v)", count, fs)
	}
}

func TestLoopbackDatastoreNotFlagged(t *testing.T) {
	ss := `LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=888,fd=5))
LISTEN 0 128 [::1]:5432 [::]:* users:(("postgres",pid=888,fd=6))`
	fs, err := New().Check(context.Background(), platform.Env{Runner: fakeRunner{ss: ss}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("loopback-bound datastore should not be flagged, got %v", fs)
	}
}

func TestAdminPanelFlagged(t *testing.T) {
	ss := `LISTEN 0 128 0.0.0.0:9000 0.0.0.0:* users:(("portainer",pid=42,fd=3))`
	fs, err := New().Check(context.Background(), platform.Env{Runner: fakeRunner{ss: ss}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "ports.exposed-admin"); !ok {
		t.Fatalf("expected ports.exposed-admin, got %v", fs)
	}
}

func TestGenericExposedOnlyWithoutFirewall(t *testing.T) {
	ss := `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("myapp",pid=7,fd=3))`

	// No firewall active -> the generic exposure finding appears (SSH excluded).
	noFW := fakeRunner{ss: ss, missing: map[string]bool{"ufw": true, "firewall-cmd": true, "nft": true}}
	fs, err := New().Check(context.Background(), platform.Env{Runner: noFW})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "ports.exposed")
	if !ok {
		t.Fatalf("expected ports.exposed with no firewall, got %v", fs)
	}
	if f.Severity != model.SeverityLow {
		t.Errorf("generic exposure severity = %v, want low", f.Severity)
	}
	if strings.Contains(f.Evidence["ports"], "22") {
		t.Errorf("SSH port must be excluded from generic exposure, got %q", f.Evidence["ports"])
	}
	if !strings.Contains(f.Evidence["ports"], "8080") {
		t.Errorf("expected port 8080 listed, got %q", f.Evidence["ports"])
	}

	// Active ufw firewall -> no generic finding (firewall is the backstop).
	withFW := fakeRunner{ss: ss, outputs: map[string]string{"ufw status": "Status: active\n"}}
	fs2, err := New().Check(context.Background(), platform.Env{Runner: withFW})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs2, "ports.exposed"); ok {
		t.Errorf("generic exposure should be suppressed when a firewall is active, got %v", fs2)
	}
}

func TestMalformedLinesSkipped(t *testing.T) {
	ss := "garbage line without enough fields\nLISTEN\n\n"
	fs, err := New().Check(context.Background(), platform.Env{Runner: fakeRunner{ss: ss, missing: map[string]bool{"ufw": true, "firewall-cmd": true, "nft": true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("malformed ss output should yield no findings, got %v", fs)
	}
}
