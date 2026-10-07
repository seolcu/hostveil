package fix_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	agentcheck "github.com/seolcu/hostveil/internal/check/agent"
	"github.com/seolcu/hostveil/internal/fix"
)

// An OpenClaw gateway bound to the LAN with authentication off, and its
// sandbox off: the three agent findings that used to be declined.
func agentRiskyHost(t *testing.T, dir string) check.Checker {
	t.Helper()
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(home, ".openclaw", "openclaw.json")
	writeFixture(t, config, `{
  // the operator's own comment, which the edit must keep
  "gateway": {"bind": "lan", "auth": {"mode": "none"}},
  "agents": {"defaults": {"sandbox": {"mode": "off"}}},
}
`)
	if err := os.Chmod(config, 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	writeFixture(t, passwd, "opuser:x:1000:1000:Agent Operator:"+home+":/bin/bash\n")
	return &agentcheck.Checker{PasswdPath: passwd, Runtimes: agentcheck.DefaultRuntimes()}
}

func TestRiskyAgentFixesClearTheirFindings(t *testing.T) {
	for id, alsoClears := range map[string][]string{
		"agent.sandbox-off": nil,
		// Off the network, no authentication is the runtime's own
		// single-user default, so rebinding answers both findings.
		"agent.gateway-exposed": {"agent.auth-disabled"},
		"agent.auth-disabled":   {"agent.gateway-exposed"},
	} {
		t.Run(id, func(t *testing.T) {
			checker := agentRiskyHost(t, t.TempDir())
			before := runChecker(t, checker)
			f, ok := before[id]
			if !ok {
				t.Fatalf("not flagged; found %v", keysOf(before))
			}
			fx, _, err := fix.Default().Build(f)
			if err != nil {
				t.Fatal(err)
			}
			if !fx.IndividualOnly || fx.Actions[0].Warning == "" {
				t.Errorf("%s must be individual-only with a warning", id)
			}
			in, out := applyFirstAlternative(t, f)
			after := runChecker(t, checker)
			for _, gone := range append([]string{id}, alsoClears...) {
				if _, still := after[gone]; still {
					t.Errorf("%s survived.\n--- before ---\n%s\n--- after ---\n%s", gone, in, out)
				}
			}
			if !strings.Contains(string(out), "the operator's own comment") {
				t.Errorf("the edit dropped the operator's comment:\n%s", out)
			}
		})
	}
}
