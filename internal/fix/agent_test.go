package fix

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// seededOpenClawConfig is the shape of config these fixes actually meet: the
// commented, trailing-comma JSON5 a self-hoster writes while trying to make
// the thing work. demo/seed/openclaw.json is the same file, and it exists
// because a fixture that parses only as strict JSON would not exercise the
// case the whole editor was written for.
const seededOpenClawConfig = `{
  "gateway": {
    // "so I can reach it from the tablet in the kitchen"
    "bind": "lan",
    "controlUi": {
      // "the login kept logging me out while I was setting it up"
      "allowInsecureAuth": true,
    },
  },

  "tools": {
    // "approving every command got annoying fast"
    "exec": { "security": "full", "ask": "off" },
    // "it couldn't restart my containers without this"
    "elevated": { "enabled": true },
  },

  // A URL, to prove the comment stripper does not mistake the "//" inside a
  // string literal for the start of a comment.
  "notes": "hardening guide: https://docs.openclaw.ai/gateway/security",
}
`

func agentFinding(id string, ev map[string]string) model.Finding {
	opts := []model.FindingOption{model.WithService("alice:openclaw")}
	for k, v := range ev {
		opts = append(opts, model.WithEvidence(k, v))
	}
	return model.NewFinding(id, "t", model.SeverityHigh, model.SourceAgent, model.RemediationReview, opts...)
}

// One safe value is one action, which is the Auto shape. Two are two
// independent alternatives, which is the Review shape. Neither is decided
// here — both are read off the evidence the checker recorded.
func TestAgentConfigKeyShapeFollowsTheSafeValues(t *testing.T) {
	auto := agentFinding("agent.elevated-enabled", map[string]string{
		"config": "/home/alice/.openclaw/openclaw.json",
		"set":    "tools.elevated.enabled=false",
	})
	fx, err := buildAgentConfigKey(auto)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if fx.Kind != model.RemediationAuto || len(fx.Actions) != 1 {
		t.Errorf("one safe value should be an Auto fix with one action, got %v with %d", fx.Kind, len(fx.Actions))
	}
	if err := Validate(fx); err != nil {
		t.Errorf("Validate: %v", err)
	}

	review := agentFinding("agent.exec-unrestricted", map[string]string{
		"config":  "/home/alice/.openclaw/openclaw.json",
		"set":     `tools.exec.security="deny", tools.exec.ask="always"`,
		"set-alt": `tools.exec.security="ask", tools.exec.ask="always"`,
	})
	fx, err = buildAgentConfigKey(review)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if fx.Kind != model.RemediationReview || len(fx.Actions) != 2 {
		t.Errorf("two safe values should be a Review fix with two alternatives, got %v with %d", fx.Kind, len(fx.Actions))
	}
	if err := Validate(fx); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// The point of the whole exercise: the operator's comments survive, and the
// change is confined to the keys the finding named.
func TestAgentConfigKeyTransformKeepsTheOperatorsFile(t *testing.T) {
	f := agentFinding("agent.exec-unrestricted", map[string]string{
		"config":  "/home/alice/.openclaw/openclaw.json",
		"set":     `tools.exec.security="deny", tools.exec.ask="always"`,
		"set-alt": `tools.exec.security="ask", tools.exec.ask="always"`,
	})
	fx, err := buildAgentConfigKey(f)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	for i, a := range fx.Actions {
		out, err := a.Transform([]byte(seededOpenClawConfig))
		if err != nil {
			t.Fatalf("alternative %d: %v", i, err)
		}
		got := string(out)
		for _, keep := range []string{
			`// "approving every command got annoying fast"`,
			`// "the login kept logging me out while I was setting it up"`,
			`"notes": "hardening guide: https://docs.openclaw.ai/gateway/security"`,
			`"bind": "lan"`,
			`"allowInsecureAuth": true`,
		} {
			if !strings.Contains(got, keep) {
				t.Errorf("alternative %d dropped %q:\n%s", i, keep, got)
			}
		}
		if strings.Contains(got, `"security": "full"`) {
			t.Errorf("alternative %d left the dangerous value in place:\n%s", i, got)
		}
		if !strings.Contains(got, `"ask": "always"`) {
			t.Errorf("alternative %d did not set the approval prompt back:\n%s", i, got)
		}
	}

	// The two alternatives differ, and they differ in exactly the one key
	// the operator is being asked to choose about.
	a0, _ := fx.Actions[0].Transform([]byte(seededOpenClawConfig))
	a1, _ := fx.Actions[1].Transform([]byte(seededOpenClawConfig))
	if !strings.Contains(string(a0), `"security": "deny"`) {
		t.Errorf("first alternative should write deny:\n%s", a0)
	}
	if !strings.Contains(string(a1), `"security": "ask"`) {
		t.Errorf("second alternative should write ask:\n%s", a1)
	}
}

// The read must refuse a symlink. This path is inside an account's own home,
// so the account controls it, and hostveil is root.
func TestAgentConfigKeyRefusesToFollowSymlinks(t *testing.T) {
	fx, err := buildAgentConfigKey(agentFinding("agent.ssrf-private-network", map[string]string{
		"config": "/home/alice/.openclaw/openclaw.json",
		"set":    "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork=false",
	}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i, a := range fx.Actions {
		if !a.NoFollow {
			t.Errorf("action %d edits a path under a user's home without NoFollow", i)
		}
	}
}

// A key that has gone from the config since the scan is a config nobody has
// looked at, and writing to it on the strength of a stale finding is worse
// than declining.
func TestAgentConfigKeyRefusesAKeyThatHasSinceGone(t *testing.T) {
	fx, err := buildAgentConfigKey(agentFinding("agent.elevated-enabled", map[string]string{
		"config": "/home/alice/.openclaw/openclaw.json",
		"set":    "tools.elevated.enabled=false",
	}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = fx.Actions[0].Transform([]byte(`{"gateway":{"bind":"lan"}}`))
	if err == nil {
		t.Fatal("transform wrote to a config that no longer sets the key")
	}
	if !strings.Contains(err.Error(), "re-scan") {
		t.Errorf("the error should tell the operator to re-scan, got: %v", err)
	}
}

func TestAgentConfigKeyRefusesFindingsItCannotTrust(t *testing.T) {
	cases := map[string]map[string]string{
		"no config path":     {"set": "tools.elevated.enabled=false"},
		"no set evidence":    {"config": "/home/alice/.openclaw/openclaw.json"},
		"malformed pair":     {"config": "/x", "set": "tools.elevated.enabled"},
		"value is not JSON":  {"config": "/x", "set": "tools.elevated.enabled=nope"},
		"empty set evidence": {"config": "/x", "set": " "},
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := buildAgentConfigKey(agentFinding("agent.elevated-enabled", ev)); err == nil {
				t.Error("built a fix from evidence it should not trust")
			}
		})
	}
}

// The JSON literal in the evidence is what keeps false distinguishable from
// "false". A boolean key written as a string would be a config the runtime
// reads differently while hostveil reports the finding fixed.
func TestAgentConfigKeyPreservesValueTypes(t *testing.T) {
	fx, err := buildAgentConfigKey(agentFinding("agent.control-ui-insecure", map[string]string{
		"config": "/home/alice/.openclaw/openclaw.json",
		"set":    "gateway.controlUi.allowInsecureAuth=false",
	}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	out, err := fx.Actions[0].Transform([]byte(seededOpenClawConfig))
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(string(out), `"allowInsecureAuth": false,`) {
		t.Errorf("boolean written as something else:\n%s", out)
	}
	if strings.Contains(string(out), `"allowInsecureAuth": "false"`) {
		t.Error("a boolean was written as a string")
	}
}
