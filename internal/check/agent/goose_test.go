package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
)

const gooseConfig = ".config/goose/config.yaml"

func gooseScan(t *testing.T, h *host, ss string) []model.Finding {
	t.Helper()
	fs, err := h.checker().Check(context.Background(), envNoFirewall(ss))
	if err != nil {
		t.Fatalf("nothing went unexamined: %v", err)
	}
	return fs
}

func TestGooseModeAutoIsExecUnrestricted(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", gooseConfig, "GOOSE_PROVIDER: openai\nGOOSE_MODE: auto\n", 0o600)

	f, ok := findByID(gooseScan(t, h, ""), "agent.exec-unrestricted")
	if !ok {
		t.Fatal("GOOSE_MODE: auto approves every tool call and must be reported")
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.Remediation != model.RemediationManual {
		t.Errorf("remediation = %v, want Manual: the JSON5 editor cannot write YAML", f.Remediation)
	}
	if f.Evidence["unset"] != "" {
		t.Errorf("an explicit auto is not a default: unset = %q", f.Evidence["unset"])
	}
	if f.Evidence["set"] != "" {
		t.Errorf("a Manual finding must carry no values to write, got %q", f.Evidence["set"])
	}
}

// The case the rule exists for. Goose's default is auto, so the host where
// nobody chose a mode is running the one that approves everything — and a
// rule that fired only on an explicit value would call it clean.
func TestGooseModeUnsetIsTheDefaultAuto(t *testing.T) {
	for name, write := range map[string]func(h *host){
		"key absent":  func(h *host) { h.write("alice", gooseConfig, "GOOSE_PROVIDER: openai\n", 0o600) },
		"file absent": func(h *host) { h.mkdir("alice", ".config/goose", 0o700) },
		"file empty":  func(h *host) { h.write("alice", gooseConfig, "", 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t, "alice")
			write(h)
			f, ok := findByID(gooseScan(t, h, ""), "agent.exec-unrestricted")
			if !ok {
				t.Fatal("an unset GOOSE_MODE is auto and must be reported")
			}
			if !strings.Contains(f.Evidence["unset"], "GOOSE_MODE") {
				t.Errorf("the finding must say the value is a default, not a setting: %v", f.Evidence)
			}
		})
	}
}

func TestGooseSaferModesAreClean(t *testing.T) {
	for _, mode := range []string{"approve", "smart_approve", "chat"} {
		h := newHost(t, "alice")
		h.write("alice", gooseConfig, "GOOSE_MODE: "+mode+"\n", 0o600)
		if f, ok := findByID(gooseScan(t, h, ""), "agent.exec-unrestricted"); ok {
			t.Errorf("GOOSE_MODE: %s flagged: %v", mode, f.Evidence)
		}
	}
}

// "I could not look" is not "the default applies". An unreadable config
// might say approve; inventing the default's finding for it would be a
// finding about a guess.
func TestGooseUnreadableConfigDegradesWithoutAFinding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	h := newHost(t, "alice")
	h.write("alice", gooseConfig, "GOOSE_MODE: approve\n", 0)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("an unreadable config must degrade the domain, got %v", err)
	}
	if f, ok := findByID(fs, "agent.exec-unrestricted"); ok {
		t.Errorf("reported a default for a config it could not read: %v", f.Evidence)
	}
}

// Goose writes its keyring fallback as YAML, not KEY=value; reading it with
// the env parser would see no keys and pass a world-readable file of API
// keys as empty.
func TestGooseSecretsYAMLIsReadAsYAML(t *testing.T) {
	const secrets = "OPENAI_API_KEY: sk-notarealkeybutlongenough\nGOOSE_PROVIDER__HOST: https://api.openai.com\n"

	h := newHost(t, "alice")
	h.write("alice", gooseConfig, "GOOSE_MODE: approve\n", 0o600)
	h.write("alice", ".config/goose/secrets.yaml", secrets, 0o644)
	f, ok := findByID(gooseScan(t, h, ""), "agent.secret-exposed")
	if !ok {
		t.Fatal("a 0644 secrets.yaml holding a real key must be reported")
	}
	if f.Evidence["keys"] != "OPENAI_API_KEY" {
		t.Errorf("keys = %q, want only OPENAI_API_KEY", f.Evidence["keys"])
	}

	h2 := newHost(t, "bob")
	h2.write("bob", gooseConfig, "GOOSE_MODE: approve\n", 0o600)
	h2.write("bob", ".config/goose/secrets.yaml", secrets, 0o600)
	if _, ok := findByID(gooseScan(t, h2, ""), "agent.secret-exposed"); ok {
		t.Error("Goose writes this file 0600 itself; that is correct and must not be flagged")
	}

	h3 := newHost(t, "carol")
	h3.write("carol", gooseConfig, "GOOSE_MODE: approve\n", 0o600)
	h3.write("carol", ".config/goose/secrets.yaml", "GOOSE_PROVIDER: openai\n", 0o644)
	if _, ok := findByID(gooseScan(t, h3, ""), "agent.secret-exposed"); ok {
		t.Error("a readable file with no credentials in it is not a leak")
	}
}

// goose web's bind is a flag, so the listener is the whole answer — and it
// is attributed by process name, on whatever port it chose.
func TestGooseWebListenerIsAttributedByProcess(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", gooseConfig, "GOOSE_MODE: approve\n", 0o600)

	f, ok := findByID(gooseScan(t, h, ssLine("0.0.0.0", 8088, "goose")), "agent.gateway-exposed")
	if !ok {
		t.Fatal("goose web on 0.0.0.0 must be reported whatever port it was given")
	}
	if f.Evidence["port"] != "8088" || f.Evidence["process"] != "goose" {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

// Port 3000 is Grafana's as often as anybody's.
func TestGooseDoesNotClaimSomeoneElsesPort(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", gooseConfig, "GOOSE_MODE: approve\n", 0o600)

	ss := strings.Join([]string{
		ssLine("0.0.0.0", 3000, "grafana"),
		ssLine("0.0.0.0", 3000, ""),
		ssLine("127.0.0.1", 3000, "goose"),
	}, "\n")
	if f, ok := findByID(gooseScan(t, h, ss), "agent.gateway-exposed"); ok {
		t.Errorf("attributed a listener Goose does not own: %v", f.Evidence)
	}
}
