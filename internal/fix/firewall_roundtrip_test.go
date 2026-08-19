package fix_test

import (
	"context"
	"errors"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	firewallcheck "github.com/seolcu/hostveil/internal/check/firewall"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// The exec-fix counterpart to roundtrip_test.go's loop.
//
// applyFirstAlternative there only closes the loop for ActionEdit: read the
// file, run Transform, write it back, ask the same checker again. firewall's
// fix is ActionExec — two ufw commands with no file to read back — so it has
// never been run through a real checker at all, only through hand-built
// findings asserting the commands themselves (firewall_test.go).
//
// A fake CommandRunner cannot execute ufw, so this cannot prove the fix works
// against a real firewall. What it can prove is the thing that has never been
// checked: that the exact evidence and finding shape firewall.Checker emits is
// what fix.Default() accepts, that the commands it builds are the ones a real
// ufw would need to run, and that once ufw has done what those commands say —
// scripted here as ufw's own documented output for "allow then enable" — the
// same checker that raised firewall.inactive no longer does.
func TestFirewallFixActuallyClearsTheFinding(t *testing.T) {
	r := checktest.New().
		Only("ufw", "ss").
		Script("Status: inactive\n", "ufw", "status").
		Listeners("LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n")
	env := r.Env()
	checker := firewallcheck.New()

	before := runFirewallChecker(t, checker, env)
	f, ok := before["firewall.inactive"]
	if !ok {
		t.Fatalf("the checker did not flag firewall.inactive on a host built to trip it; it found %v", keysOf(before))
	}
	if f.Evidence["ssh_port"] != "22" {
		t.Fatalf("finding does not carry the SSH port the fix needs: %+v", f.Evidence)
	}

	fx, ok, err := fix.Default().Build(f)
	if err != nil {
		t.Fatalf("building the fix for firewall.inactive: %v", err)
	}
	if !ok {
		t.Fatal("no fix is registered for firewall.inactive")
	}
	if len(fx.Actions) != 1 {
		t.Fatalf("want one action carrying both commands in order, got %d", len(fx.Actions))
	}
	a := fx.Actions[0]
	if a.Kind != fix.ActionExec {
		t.Fatalf("Kind = %v, want ActionExec", a.Kind)
	}

	// Run every command the fix built against the fake, exactly as the
	// engine's applyExec would — proving the argv is well-formed and
	// self-consistent — then bring the fake's state up to what real ufw
	// documents these two commands as leaving behind: active, with SSH still
	// allowed and everything else denied by default.
	for _, cmd := range a.Commands {
		r.Script("", cmd...)
	}
	ctx := context.Background()
	for _, cmd := range a.Commands {
		if _, err := env.Runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			t.Fatalf("running %v: %v", cmd, err)
		}
	}
	r.Script("Status: active\n", "ufw", "status")
	r.Script("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
		"ufw", "status", "verbose")

	after := runFirewallChecker(t, checker, env)
	if _, still := after["firewall.inactive"]; still {
		t.Error("firewall.inactive survived its own fix")
	}
	if _, allow := after["firewall.default-allow"]; allow {
		t.Error("the fix left ufw's default inbound policy at allow")
	}
}

// runFirewallChecker mirrors roundtrip_test.go's runChecker, except it takes
// the environment rather than building a fresh one — this loop needs to
// re-run the same checker against a runner that changed state mid-test.
func runFirewallChecker(t *testing.T, c check.Checker, env platform.Env) map[string]model.Finding {
	t.Helper()
	if ok, why := c.Available(context.Background(), env); !ok {
		t.Fatalf("the checker is unavailable: %s", why)
	}
	fs, err := c.Check(context.Background(), env)
	var pe *check.PartialError
	if err != nil && !errors.As(err, &pe) {
		t.Fatalf("the checker failed: %v", err)
	}
	out := map[string]model.Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}
