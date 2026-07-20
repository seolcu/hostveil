package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// fakeRunner scripts `ss` output and controls which binaries appear present,
// which is what firewall.Probe keys off.
type fakeRunner struct {
	ss      string
	ssErr   error
	missing map[string]bool
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
		return []byte(f.ss), f.ssErr
	}
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if out, ok := f.outputs[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("no output for: " + key)
}

// noFirewall reports every firewall front-end as absent, which Probe reads as
// a definite StatusInactive rather than "could not look".
func noFirewall() map[string]bool {
	return map[string]bool{"ufw": true, "firewall-cmd": true, "nft": true}
}

func envNoFirewall(ss string) platform.Env {
	return platform.Env{Runner: fakeRunner{ss: ss, missing: noFirewall()}}
}

func envActiveFirewall(ss string) platform.Env {
	return platform.Env{Runner: fakeRunner{
		ss:      ss,
		missing: map[string]bool{"firewall-cmd": true, "nft": true},
		outputs: map[string]string{"ufw status": "Status: active"},
	}}
}

// ssLine renders one `ss -tlnp` row.
func ssLine(addr string, port int, proc string) string {
	p := "users:((\"" + proc + "\",pid=1,fd=3))"
	if proc == "" {
		p = ""
	}
	return fmt.Sprintf("LISTEN 0 128 %s:%d 0.0.0.0:* %s", addr, port, p)
}

// host is a synthetic /etc/passwd plus real temp home directories, so the
// checker exercises genuine absolute paths and real permission bits.
type host struct {
	t      *testing.T
	passwd string
	homes  map[string]string
}

func newHost(t *testing.T, users ...string) *host {
	t.Helper()
	root := t.TempDir()
	h := &host{t: t, passwd: filepath.Join(root, "passwd"), homes: map[string]string{}}

	// A service account and a nobody entry that must both be ignored.
	lines := []string{
		"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin",
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
	}
	for i, u := range users {
		home := filepath.Join(root, u)
		if err := os.MkdirAll(home, 0o755); err != nil {
			t.Fatal(err)
		}
		h.homes[u] = home
		lines = append(lines, fmt.Sprintf("%s:x:%d:%d::%s:/bin/bash", u, 1000+i, 1000+i, home))
	}
	if err := os.WriteFile(h.passwd, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *host) write(user, rel, content string, mode os.FileMode) string {
	h.t.Helper()
	p := filepath.Join(h.homes[user], rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *host) mkdir(user, rel string, mode os.FileMode) string {
	h.t.Helper()
	p := filepath.Join(h.homes[user], rel)
	if err := os.MkdirAll(p, 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *host) checker() *Checker {
	return &Checker{PasswdPath: h.passwd, Runtimes: defaultRuntimes()}
}

func findByID(fs []model.Finding, id string) (model.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func countByID(fs []model.Finding, id string) int {
	n := 0
	for _, f := range fs {
		if f.ID == id {
			n++
		}
	}
	return n
}

// A loopback-bound, authenticated, correctly-permissioned install. Anything
// this produces a finding for is noise.
const cleanOpenClaw = `{"gateway":{"bind":"loopback","auth":{"mode":"token","token":"a-long-random-token"}}}`

// --- Available -------------------------------------------------------------

// "I could not look" and "there was nothing there" are different facts. They
// both skip the domain, but collapsing them is how a scan starts reporting a
// clean result for ground it never covered.
func TestAvailableDistinguishesUnreadableFromAbsent(t *testing.T) {
	h := newHost(t, "alice")

	c := &Checker{PasswdPath: filepath.Join(t.TempDir(), "nope"), Runtimes: defaultRuntimes()}
	ok, reason := c.Available(context.Background(), platform.Env{})
	if ok {
		t.Error("expected unavailable when passwd is unreadable")
	}
	if !strings.Contains(reason, "cannot read") {
		t.Errorf("reason %q should say we could not look", reason)
	}

	ok, reason = h.checker().Available(context.Background(), platform.Env{})
	if ok {
		t.Error("expected unavailable when no runtime is installed")
	}
	if !strings.Contains(reason, "no self-hosted agent runtime") {
		t.Errorf("reason %q should say nothing was installed", reason)
	}
	if strings.Contains(reason, "cannot read") {
		t.Errorf("reason %q conflates absence with unreadability", reason)
	}
}

func TestAvailableTrueWhenMarkerExists(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)

	if ok, reason := h.checker().Available(context.Background(), platform.Env{}); !ok {
		t.Errorf("expected available once .openclaw exists, got %q", reason)
	}
}

// --- Config parsing --------------------------------------------------------

// OpenClaw documents its config as JSON5 and users comment it heavily. If a
// commented config were unparseable, every OpenClaw host would report
// Degraded, and a flag that fires everywhere tells an operator nothing.
func TestJSON5ConfigWithCommentsAndTrailingCommasParses(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{
  // the gateway is on the LAN so the family tablet can reach it
  "gateway": {
    "bind": "lan",           // not loopback!
    "auth": { "mode": "none" },   /* nobody else is on this network */
  },
  "notes": "a url with // inside must survive: https://example.com/x",
}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatalf("a commented JSON5 config must not degrade: %v", err)
	}
	if _, ok := findByID(fs, "agent.gateway-exposed"); !ok {
		t.Error("bind: lan should have been read out of the JSON5 config")
	}
	if _, ok := findByID(fs, "agent.auth-disabled"); !ok {
		t.Error("auth.mode: none should have been read out of the JSON5 config")
	}
}

// An unparseable config is our blind spot, not the operator's defect, so it
// costs coverage without inventing a finding to explain itself.
func TestUnparseableConfigDegradesWithoutInventingAFinding(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", "{{{ this is not a config", 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError, got %v", err)
	}
	if partial.Covered != 0 || partial.Total != 1 {
		t.Errorf("coverage = %d/%d, want 0/1", partial.Covered, partial.Total)
	}
	for _, f := range fs {
		if strings.Contains(strings.ToLower(f.Title), "pars") {
			t.Errorf("a parse failure must not become a finding: %q", f.Title)
		}
	}
}

// An install with no config file at all is a normal state, not partial
// coverage — there is nothing we failed to read.
func TestInstalledButUnconfiguredDoesNotDegrade(t *testing.T) {
	h := newHost(t, "alice")
	h.mkdir("alice", ".openclaw", 0o700)

	if _, err := h.checker().Check(context.Background(), envNoFirewall("")); err != nil {
		t.Errorf("an unconfigured install must not degrade the domain: %v", err)
	}
}

// --- Gateway exposure ------------------------------------------------------

// The firewall decides how loud the finding is, never whether it is true.
func TestGatewayExposureSeverityMatrix(t *testing.T) {
	exposedCfg := `{"gateway":{"bind":"lan","auth":{"mode":"token","token":"a-long-random-token"}}}`
	listening := ssLine("0.0.0.0", 18789, "openclaw")

	cases := []struct {
		name string
		cfg  string
		env  platform.Env
		want model.Severity
		ok   bool
		why  string
	}{
		{"config only, nothing listening", exposedCfg, envNoFirewall(""), model.SeverityHigh, true,
			"configured intent is enough to report, but nothing is confirmed reachable yet"},
		{"listening, firewall active", exposedCfg, envActiveFirewall(listening), model.SeverityHigh, true,
			"a firewall is a real backstop, so this is not the worst case"},
		{"listening, no firewall", exposedCfg, envNoFirewall(listening), model.SeverityCritical, true,
			"reachable right now with nothing in front of it"},
		{"loopback and quiet", cleanOpenClaw, envNoFirewall(""), 0, false,
			"the correct configuration must produce no finding at all"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHost(t, "alice")
			h.write("alice", ".openclaw/openclaw.json", c.cfg, 0o600)

			fs, err := h.checker().Check(context.Background(), c.env)
			if err != nil {
				t.Fatal(err)
			}
			f, ok := findByID(fs, "agent.gateway-exposed")
			if ok != c.ok {
				t.Fatalf("finding present = %v, want %v — %s", ok, c.ok, c.why)
			}
			if ok && f.Severity != c.want {
				t.Errorf("severity = %v, want %v — %s", f.Severity, c.want, c.why)
			}
		})
	}
}

// A listener the config never predicted still counts: the operator may have
// configured one thing and be running another.
func TestListenerAloneExposesGateway(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(ssLine("0.0.0.0", 18789, "openclaw")))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.gateway-exposed")
	if !ok {
		t.Fatal("an observed non-loopback listener on the gateway port must be reported")
	}
	if got := f.Evidence["basis"]; got != "listener" {
		t.Errorf("basis = %q, want \"listener\" — the config said loopback", got)
	}
}

// These runtimes appear in ss under whatever interpreter runs them, so a
// process name must never be enough on its own to call a socket an agent
// gateway. An unrelated python3 or node service on some other port is not
// evidence of anything, and attributing it would put a Critical on a host
// that is not running the runtime at all.
func TestUnrelatedInterpreterProcessIsNotAGateway(t *testing.T) {
	h := newHost(t, "alice")
	// Hermes is installed but its dashboard is not running; the python3 here
	// is an ordinary service on an unrelated port.
	h.write("alice", ".hermes/.env", "LOG_LEVEL=debug\n", 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(ssLine("0.0.0.0", 8000, "python3")))
	if err != nil {
		t.Fatal(err)
	}
	if f, ok := findByID(fs, "agent.gateway-exposed"); ok {
		t.Errorf("a python3 listener on port 8000 was mistaken for a gateway: %+v", f.Evidence)
	}
}

// Among several listeners on the gateway port, the one the runtime plausibly
// owns is the one worth naming in evidence.
func TestListenerEvidencePrefersTheRuntimesOwnProcess(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)

	ss := ssLine("0.0.0.0", 18789, "haproxy") + "\n" + ssLine("192.168.1.5", 18789, "openclaw")
	fs, err := h.checker().Check(context.Background(), envNoFirewall(ss))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.gateway-exposed")
	if !ok {
		t.Fatal("expected the gateway to be reported")
	}
	if got := f.Evidence["process"]; got != "openclaw" {
		t.Errorf("evidence names %q, want the runtime's own process", got)
	}
}

// A loopback listener on the gateway port is the correct deployment.
func TestLoopbackListenerIsNotExposure(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(ssLine("127.0.0.1", 18789, "openclaw")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "agent.gateway-exposed"); ok {
		t.Error("a loopback-bound gateway is not exposed")
	}
}

// `ss` is a corroborator, not a source of coverage. Losing it costs sharper
// severity, not ground, so it must not degrade the domain.
func TestMissingSsDoesNotDegrade(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{"gateway":{"bind":"lan","auth":{"mode":"token","token":"a-long-random-token"}}}`, 0o600)

	env := platform.Env{Runner: fakeRunner{ssErr: errors.New("ss: not found"), missing: noFirewall()}}
	fs, err := h.checker().Check(context.Background(), env)
	if err != nil {
		t.Fatalf("a missing ss must not degrade the domain: %v", err)
	}
	f, ok := findByID(fs, "agent.gateway-exposed")
	if !ok {
		t.Fatal("the configured bind alone should still report exposure")
	}
	if got := f.Evidence["basis"]; got != "config" {
		t.Errorf("basis = %q, want \"config\"", got)
	}
}

// --- Authentication --------------------------------------------------------

// auth.mode: none on a loopback gateway is upstream's documented single-user
// default. Flagging it would put a Critical on a correct install — a score
// nobody could improve by doing everything right.
func TestAuthDisabledIsSilentOnALoopbackGateway(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{"gateway":{"bind":"loopback","auth":{"mode":"none"}}}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "agent.auth-disabled"); ok {
		t.Error("no-auth on loopback is the legitimate default and must not be flagged")
	}
}

func TestAuthDisabledFiresOnAnExposedGateway(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{"gateway":{"bind":"lan","auth":{"mode":"none"}}}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.auth-disabled")
	if !ok {
		t.Fatal("an exposed gateway with no authentication must be reported")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
}

// OpenClaw fails closed when the auth mode is unset, so an absent key is not
// the open case and must not be reported as one.
func TestUnsetAuthModeIsNotTreatedAsDisabled(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{"gateway":{"bind":"lan"}}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "agent.auth-disabled"); ok {
		t.Error("an unset auth mode fails closed upstream; reporting it is a false positive")
	}
}

// --- Danger keys -----------------------------------------------------------

func TestEachDangerKeyTriggersItsFinding(t *testing.T) {
	cases := []struct {
		cfg string
		id  string
	}{
		{`{"tools":{"exec":{"security":"full"}}}`, "agent.exec-unrestricted"},
		{`{"tools":{"exec":{"ask":"off"}}}`, "agent.exec-unrestricted"},
		{`{"tools":{"elevated":{"enabled":true}}}`, "agent.elevated-enabled"},
		{`{"agents":{"defaults":{"sandbox":{"mode":"off"}}}}`, "agent.sandbox-off"},
		{`{"gateway":{"controlUi":{"allowInsecureAuth":true}}}`, "agent.control-ui-insecure"},
		{`{"gateway":{"controlUi":{"dangerouslyDisableDeviceAuth":true}}}`, "agent.control-ui-insecure"},
		{`{"browser":{"ssrfPolicy":{"dangerouslyAllowPrivateNetwork":true}}}`, "agent.ssrf-private-network"},
	}
	for _, c := range cases {
		t.Run(c.id+" via "+c.cfg[:20], func(t *testing.T) {
			h := newHost(t, "alice")
			h.write("alice", ".openclaw/openclaw.json", c.cfg, 0o600)

			fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := findByID(fs, c.id); !ok {
				t.Errorf("config %s did not produce %s", c.cfg, c.id)
			}
		})
	}
}

// Two keys describing the same weakening are one problem, and the operator
// should see it once — with both keys named.
func TestSharedIDDangerRulesCollapseToOneFinding(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{"tools":{"exec":{"security":"full","ask":"off"}}}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if n := countByID(fs, "agent.exec-unrestricted"); n != 1 {
		t.Fatalf("got %d exec findings, want exactly 1", n)
	}
	f, _ := findByID(fs, "agent.exec-unrestricted")
	for _, want := range []string{"tools.exec.security", "tools.exec.ask"} {
		if !strings.Contains(f.Evidence["settings"], want) {
			t.Errorf("evidence %q should name %s", f.Evidence["settings"], want)
		}
	}
}

func TestSafeConfigProducesNoDangerFindings(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json",
		`{"gateway":{"bind":"loopback","auth":{"mode":"token","token":"a-long-random-token"}},
		  "tools":{"exec":{"security":"deny","ask":"always"},"elevated":{"enabled":false}}}`, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a hardened install must be clean, got %d findings: %+v", len(fs), fs)
	}
}

// --- Permissions and secrets ----------------------------------------------

func TestLooseConfigModeIsReportedInTheShapeTheFixNeeds(t *testing.T) {
	h := newHost(t, "alice")
	path := h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o644)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.config-perms")
	if !ok {
		t.Fatal("a 0644 config must be reported")
	}
	if f.Remediation != model.RemediationAuto {
		t.Errorf("remediation = %v, want Auto", f.Remediation)
	}
	// buildTightenMode reads exactly these two keys.
	if f.Evidence["paths"] != path {
		t.Errorf("paths = %q, want %q", f.Evidence["paths"], path)
	}
	if f.Evidence["expected"] != "0600" {
		t.Errorf("expected = %q, want \"0600\"", f.Evidence["expected"])
	}
}

func TestCompliantModesAreClean(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)
	h.mkdir("alice", ".openclaw/credentials", 0o700)
	h.mkdir("alice", ".openclaw/state", 0o700)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("upstream's own baseline must score clean, got: %+v", fs)
	}
}

func TestLooseCredentialsDirectoryIsReported(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o600)
	dir := h.mkdir("alice", ".openclaw/credentials", 0o755)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.secret-exposed")
	if !ok {
		t.Fatal("a world-readable credentials directory must be reported")
	}
	if f.Evidence["paths"] != dir || f.Evidence["expected"] != "0700" {
		t.Errorf("evidence not shaped for the mode fix: %+v", f.Evidence)
	}
}

// Hermes keeping API keys in ~/.hermes/.env is the design, not a defect. The
// actionable claim is that the file is readable by other accounts.
func TestSecretEnvIsOnlyAFindingWhenReadable(t *testing.T) {
	const env = "OPENAI_API_KEY=sk-notarealkeybutlongenough\nLOG_LEVEL=debug\n"

	h := newHost(t, "alice")
	h.write("alice", ".hermes/.env", env, 0o600)
	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "agent.secret-exposed"); ok {
		t.Error("a 0600 secrets file is correct and must not be flagged")
	}

	h2 := newHost(t, "bob")
	h2.write("bob", ".hermes/.env", env, 0o644)
	fs, err = h2.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "agent.secret-exposed")
	if !ok {
		t.Fatal("a 0644 secrets file holding a real key must be reported")
	}
	if !strings.Contains(f.Evidence["keys"], "OPENAI_API_KEY") {
		t.Errorf("evidence should name the credential key, got %q", f.Evidence["keys"])
	}
	if strings.Contains(f.Evidence["keys"], "LOG_LEVEL") {
		t.Errorf("non-credential keys should not be listed, got %q", f.Evidence["keys"])
	}
}

// A readable env file with nothing credential-shaped in it is not a secrets
// leak; reporting it would be unactionable noise.
func TestReadableEnvWithoutCredentialsIsNotASecretFinding(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".hermes/.env", "LOG_LEVEL=debug\nTZ=UTC\n", 0o644)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := findByID(fs, "agent.secret-exposed"); ok {
		t.Error("no credentials in the file means no credential exposure")
	}
}

// The load-bearing guarantee of the whole domain: hostveil reads secrets to
// judge them and must never carry one back out. Evidence is rendered by every
// UI and persisted to disk, so a value that reaches a Finding has leaked.
func TestSecretValuesNeverReachAFinding(t *testing.T) {
	const sentinel = "sk-thisisthesentinelvalue1234567890"

	h := newHost(t, "alice")
	h.write("alice", ".hermes/.env",
		"OPENAI_API_KEY="+sentinel+"\nHERMES_DASHBOARD_BASIC_AUTH_PASSWORD="+sentinel+"\n", 0o644)
	h.write("alice", ".openclaw/openclaw.json",
		`{"gateway":{"bind":"lan","auth":{"mode":"token","token":"`+sentinel+`"}}}`, 0o644)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(ssLine("0.0.0.0", 18789, "openclaw")))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings; a test that finds nothing proves nothing here")
	}
	for _, f := range fs {
		for k, v := range f.Evidence {
			if strings.Contains(v, sentinel) {
				t.Errorf("finding %s leaked the secret via evidence[%q]", f.ID, k)
			}
		}
		for name, text := range map[string]string{
			"Title": f.Title, "Description": f.Description, "HowToFix": f.HowToFix, "Service": f.Service,
		} {
			if strings.Contains(text, sentinel) {
				t.Errorf("finding %s leaked the secret via %s", f.ID, name)
			}
		}
	}
}

// --- Attribution -----------------------------------------------------------

// Two users each running an exposed gateway are two problems. If they shared
// a Key the scorer would count one and the operator would fix one.
func TestFindingsFromDifferentUsersHaveDistinctKeys(t *testing.T) {
	h := newHost(t, "alice", "bob")
	exposed := `{"gateway":{"bind":"lan","auth":{"mode":"none"}}}`
	h.write("alice", ".openclaw/openclaw.json", exposed, 0o600)
	h.write("bob", ".openclaw/openclaw.json", exposed, 0o600)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	if n := countByID(fs, "agent.auth-disabled"); n != 2 {
		t.Fatalf("got %d auth findings, want one per user", n)
	}

	keys := map[string]bool{}
	for _, f := range fs {
		if keys[f.Key()] {
			t.Errorf("duplicate Key %q — one user's finding will mask the other's", f.Key())
		}
		keys[f.Key()] = true
	}
}

// Two mode rules under one install are two separate problems and must not
// collapse into a single Key either.
func TestModeFindingsForDifferentPathsHaveDistinctKeys(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", cleanOpenClaw, 0o644)
	h.mkdir("alice", ".openclaw/state", 0o755)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(""))
	if err != nil {
		t.Fatal(err)
	}
	var perms []model.Finding
	for _, f := range fs {
		if f.ID == "agent.config-perms" {
			perms = append(perms, f)
		}
	}
	if len(perms) != 2 {
		t.Fatalf("got %d config-perms findings, want 2 (the file and the state dir)", len(perms))
	}
	if perms[0].Key() == perms[1].Key() {
		t.Errorf("both paths share Key %q, so one would be dropped", perms[0].Key())
	}
}

// Every finding the domain can emit must survive model validation, or it is
// silently dropped after the scan — the failure the Source.Valid() bound
// exists to cause and this test exists to catch.
func TestAllEmittedFindingsValidate(t *testing.T) {
	h := newHost(t, "alice")
	h.write("alice", ".openclaw/openclaw.json", `{
		"gateway":{"bind":"lan","auth":{"mode":"none"},
			"controlUi":{"allowInsecureAuth":true}},
		"tools":{"exec":{"security":"full"},"elevated":{"enabled":true}},
		"agents":{"defaults":{"sandbox":{"mode":"off"}}},
		"browser":{"ssrfPolicy":{"dangerouslyAllowPrivateNetwork":true}}}`, 0o644)
	h.mkdir("alice", ".openclaw/credentials", 0o755)

	fs, err := h.checker().Check(context.Background(), envNoFirewall(ssLine("0.0.0.0", 18789, "openclaw")))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) < 7 {
		t.Fatalf("expected the full spread of findings, got %d", len(fs))
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %s is invalid and would be dropped: %v", f.ID, err)
		}
		if f.Source != model.SourceAgent {
			t.Errorf("finding %s has source %v, want SourceAgent", f.ID, f.Source)
		}
		if !strings.HasPrefix(f.ID, "agent.") {
			t.Errorf("finding ID %q is outside the domain's namespace", f.ID)
		}
	}
}

// Service accounts and nobody are not people running agents; probing their
// homes would be noise at best and misattribution at worst.
func TestSystemAccountsAreNotProbed(t *testing.T) {
	hs, err := homes(newHost(t, "alice").passwd)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs {
		if h.Name == "daemon" || h.Name == "nobody" {
			t.Errorf("system account %q should not be probed", h.Name)
		}
	}
	if len(hs) != 1 || hs[0].Name != "alice" {
		t.Errorf("got %+v, want just alice", hs)
	}
}
