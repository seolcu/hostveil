package fix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	agentcheck "github.com/seolcu/hostveil/internal/check/agent"
)

// The agent domain's config-key findings and their fix share one parser
// (internal/json5) over one file, the same shape that makes ssh's roundtrip
// sound: internal/check/agent/config.go's decodeConfig doc comment says so
// explicitly. agent.config-perms/secret-exposed (ActionMode) and
// agent.sandbox-off/gateway-exposed/auth-disabled (Manual, unregistered) are
// excluded.
//
// One OpenClaw config trips all four danger findings at once: gateway.bind
// is left unset, which resolves to the documented loopback default, so no
// agent.gateway-exposed finding appears to contaminate the "no other
// finding" direction, and .openclaw/credentials and .openclaw/state are
// never created, so no agent.config-perms/secret-exposed finding does
// either.
func agentRoundTripCases() []roundTrip {
	setup := func(t *testing.T, dir string) check.Checker {
		t.Helper()
		home := filepath.Join(dir, "home")
		configDir := filepath.Join(home, ".openclaw")
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(configDir, "openclaw.json")
		writeFixture(t, config, `{
  "tools": {"exec": {"security": "full"}, "elevated": {"enabled": true}},
  "gateway": {"controlUi": {"allowInsecureAuth": true}},
  "browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": true}}
}
`)
		if err := os.Chmod(config, 0o600); err != nil {
			t.Fatal(err)
		}

		passwd := filepath.Join(dir, "passwd")
		writeFixture(t, passwd, "opuser:x:1000:1000:Agent Operator:"+home+":/bin/bash\n")

		return &agentcheck.Checker{PasswdPath: passwd, Runtimes: agentcheck.DefaultRuntimes()}
	}
	ids := []string{
		"agent.exec-unrestricted", "agent.elevated-enabled",
		"agent.control-ui-insecure", "agent.ssrf-private-network",
	}
	out := make([]roundTrip, 0, len(ids))
	for _, id := range ids {
		out = append(out, roundTrip{want: id, setup: setup})
	}
	return out
}

func TestEveryAgentFixActuallyClearsTheFindingItClaimsToFix(t *testing.T) {
	for _, tc := range agentRoundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			checker := tc.setup(t, dir)

			before := runChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s on a host built to trip it; it found %v",
					tc.want, keysOf(before))
			}

			in, out := applyFirstAlternative(t, f)
			after := runChecker(t, checker)
			if _, still := after[tc.want]; still {
				t.Errorf("%s survived its own fix.\n--- before ---\n%s\n--- after ---\n%s",
					tc.want, in, out)
			}
		})
	}
}

func TestAnAgentFixClearsItsOwnFindingAndNoOther(t *testing.T) {
	for _, tc := range agentRoundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			dir := t.TempDir()
			checker := tc.setup(t, dir)

			before := runChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s", tc.want)
			}
			applyFirstAlternative(t, f)
			after := runChecker(t, checker)

			for id := range before {
				if id == tc.want {
					continue
				}
				if _, ok := after[id]; !ok {
					t.Errorf("fixing %s also cleared %s, which it does not claim to fix", tc.want, id)
				}
			}
			for id := range after {
				if _, ok := before[id]; ok {
					continue
				}
				t.Errorf("fixing %s introduced %s, which was not there before", tc.want, id)
			}
		})
	}
}
