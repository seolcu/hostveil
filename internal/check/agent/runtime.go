package agent

import (
	"os"

	"github.com/seolcu/hostveil/internal/model"
)

// ConfigFormat is how a runtime encodes its config file.
type ConfigFormat int

const (
	// FormatJSON5 is JSON plus comments and trailing commas. OpenClaw's
	// config is documented as JSON5 and users comment it freely, so a strict
	// JSON decode is only the first attempt, never the last word.
	FormatJSON5 ConfigFormat = iota
	// FormatYAML is plain YAML.
	FormatYAML
)

// ModeRule declares the strictest acceptable permission for one path inside a
// runtime's state directory, relative to the owning user's home. A path is
// flagged when perm &^ Max != 0 — the same test fileperms.Rule uses.
//
// Secret marks a path that holds raw credentials. It changes which finding is
// emitted (agent.secret-exposed rather than agent.config-perms) and, for
// files, requires that the contents actually look like credentials before the
// finding fires.
type ModeRule struct {
	Rel    string
	Max    os.FileMode
	Dir    bool
	Secret bool
}

// DangerRule is one config key whose value names a known-dangerous posture.
// Bad is compared against the value rendered as a string, so one table covers
// both string enums ("full") and booleans ("true").
//
// Several rules may share an ID: two different keys can describe the same
// weakening, and the operator should see one finding, not two.
//
// Good names the safe values this key may be set to, most-preferred first,
// and it is what makes the finding fixable. An empty Good is a deliberate
// statement rather than an omission: it means hostveil knows the value is
// dangerous and does not know which value is right, so the finding stays
// Manual. agents.defaults.sandbox.mode used to be the case, until OpenClaw's
// sandbox reference documented the values: "non-main" sandboxes every session
// but the operator's own, "all" sandboxes every one.
//
// A second entry in Good is what makes a finding Review instead of Auto: two
// safe values that do not dominate each other are a choice for the operator,
// not a sequence. tools.exec.security is deny or ask, and which one is right
// depends on whether the agent is expected to run commands at all.
//
// Unset is the value the runtime behaves as if the key held when it is absent
// — from the config, or because there is no config file at all. Leave it empty
// when absence is safe or undocumented; that is every OpenClaw key, whose
// defaults fail closed. It exists for the runtime whose default is the
// dangerous value: Goose runs with GOOSE_MODE=auto unless told otherwise, so
// the host that never wrote the key is exactly the host the rule is about,
// and a rule that fired only on an explicit "auto" would pass it as clean.
type DangerRule struct {
	ID       string
	Key      string
	Bad      []string
	Good     []any
	Unset    string
	Sev      model.Severity
	Title    string
	Desc     string
	HowToFix string
}

// GatewayDesc describes a runtime's network surface, so the checker can judge
// the configured intent and cross-check it against what the host is actually
// listening on.
type GatewayDesc struct {
	DefaultPort int    // used when PortKey is absent or unset
	PortKey     string // "" when the port is not configurable
	BindKey     string

	// BindDefault is the documented bind when BindKey is absent. Leave it
	// empty when the default is genuinely unknown: an empty resolved bind
	// means "we cannot tell from config", and the checker falls back to the
	// observed listener rather than guessing a finding into existence.
	BindDefault string

	// LoopbackOnly are bind values that mean "not reachable from the network".
	LoopbackOnly []string

	AuthKey string
	// AuthDisabled are auth values that mean "no authentication". Include ""
	// only when an unset key really does mean open; a runtime that fails
	// closed when unset must not list it.
	AuthDisabled []string

	// ProcNames are the program names ss may report for this gateway, used to
	// attribute an observed listener with more confidence than the port alone.
	ProcNames []string

	// ListenerOnly is for a gateway whose bind is not in any file hostveil
	// reads — Goose's web UI takes it from a command-line flag. With no
	// config to judge, the observed listener is the whole answer, so it must
	// be attributed by process name rather than by port: port 3000 is
	// Grafana's as often as anybody's. That is only sound because every name
	// in ProcNames is the runtime's own binary, not an interpreter; see
	// matchListener for why node and python3 could never be used this way.
	ListenerOnly bool
}

// Runtime describes one self-hosted AI agent runtime entirely as data.
// Adding a third runtime should be an entry in defaultRuntimes, not new code.
type Runtime struct {
	Name    string // short lowercase name, used in Service; never in a finding ID
	Display string

	// Markers are home-relative paths whose existence means the runtime is
	// installed for that user.
	Markers []string

	Config string // home-relative
	Format ConfigFormat

	// EnvFile is a home-relative KEY=value file, "" when the runtime has none.
	EnvFile string

	// EnvOverrides maps a dotted config key to the environment variable that
	// overrides it. Some settings (Hermes' dashboard bind) live only in the
	// env file, never in the config.
	EnvOverrides map[string]string

	Modes   []ModeRule
	Gateway GatewayDesc
	Danger  []DangerRule
}

// defaultRuntimes is the shipped registry. Every path, key, and default here
// mirrors upstream documentation; keep it that way, and prefer a small set of
// stable high-signal keys over a full port of each project's own hardening
// matrix. OpenClaw ships `openclaw security audit`, which covers its config
// exhaustively; hostveil's job is the host-observable half — what is actually
// listening, what is actually readable — scored beside the other domains.
func defaultRuntimes() []Runtime {
	return runtimes()
}

// DefaultRuntimes is defaultRuntimes, exported for one caller outside this
// package: internal/docs holds the fixtures that seed a measured host against
// the paths named here.
//
// It is exported for the same reason platform.DockerProbeArgv is. A fixture
// that writes ~/.config/openclaw/config.json instead of ~/.openclaw/openclaw.json
// does not fail — the domain reports "no agent runtime found", which is a clean
// result, on a host seeded to run two. Nothing catches that except a test that
// can read this table, and a test in this package cannot see the scripts.
func DefaultRuntimes() []Runtime { return runtimes() }

func runtimes() []Runtime {
	return []Runtime{
		{
			Name:    "openclaw",
			Display: "OpenClaw",
			Markers: []string{".openclaw"},
			Config:  ".openclaw/openclaw.json",
			Format:  FormatJSON5,
			Modes: []ModeRule{
				{Rel: ".openclaw/openclaw.json", Max: 0o600},
				{Rel: ".openclaw/credentials", Max: 0o700, Dir: true, Secret: true},
				{Rel: ".openclaw/state", Max: 0o700, Dir: true},
			},
			Gateway: GatewayDesc{
				DefaultPort: 18789,
				PortKey:     "gateway.port",
				BindKey:     "gateway.bind",
				BindDefault: "loopback",
				// "auto" and "tailnet" are not loopback, but neither is
				// plainly reachable from an untrusted network; they are
				// treated as exposed so the auth check still applies.
				LoopbackOnly: []string{"loopback"},
				AuthKey:      "gateway.auth.mode",
				// Unset is deliberately absent: OpenClaw fails closed when
				// gateway.auth.mode is unset, so an absent key is not "open".
				AuthDisabled: []string{"none"},
				// The gateway's process is "openclaw-gateway", which the kernel
				// truncates to fifteen characters in what ss reports — observed
				// on a real gateway by scripts/e2e/individual.sh.
				ProcNames: []string{"openclaw", "openclaw-gatewa", "node"},
			},
			Danger: []DangerRule{
				{
					ID: "agent.exec-unrestricted", Key: "tools.exec.security", Bad: []string{"full"},
					Good:     []any{"deny", "ask"},
					Sev:      model.SeverityHigh,
					Title:    "Agent can run shell commands without approval",
					Desc:     "The agent is allowed to execute shell commands on this host with no approval step. Anything that can steer the agent — a malicious web page it reads, a poisoned document, a message from an untrusted contact — can run commands as the user it runs as.",
					HowToFix: "Set `tools.exec.security` to `deny` (or `ask`) and `tools.exec.ask` to `always`, so command execution requires an explicit approval.",
				},
				{
					ID: "agent.exec-unrestricted", Key: "tools.exec.ask", Bad: []string{"off"},
					Good:     []any{"always"},
					Sev:      model.SeverityHigh,
					Title:    "Agent can run shell commands without approval",
					Desc:     "The agent is allowed to execute shell commands on this host with no approval step. Anything that can steer the agent — a malicious web page it reads, a poisoned document, a message from an untrusted contact — can run commands as the user it runs as.",
					HowToFix: "Set `tools.exec.ask` to `always` so command execution requires an explicit approval.",
				},
				{
					ID: "agent.elevated-enabled", Key: "tools.elevated.enabled", Bad: []string{"true"},
					Good:     []any{false},
					Sev:      model.SeverityHigh,
					Title:    "Agent is permitted to run elevated commands",
					Desc:     "Elevated mode is the documented escape hatch out of the agent's sandbox and onto the host. Combined with any path by which an attacker can influence the agent's input, it turns prompt injection into host compromise.",
					HowToFix: "Set `tools.elevated.enabled` to `false`. If some workflow genuinely needs it, restrict `tools.elevated.allowFrom` to a single trusted channel.",
				},
				{
					ID: "agent.sandbox-off", Key: "agents.defaults.sandbox.mode", Bad: []string{"off"},
					// docs.openclaw.ai/gateway/config-agents/sandbox: off,
					// non-main, all. non-main first because it keeps the
					// operator's own direct session on the host and sandboxes
					// every group and channel session, which is where
					// untrusted input arrives.
					Good:     []any{"non-main", "all"},
					Sev:      model.SeverityHigh,
					Title:    "Agent tools run unsandboxed on the host",
					Desc:     "With the sandbox off, the agent's tools run directly on the gateway host rather than in an isolated container, so a tool call that goes wrong reaches your real filesystem and network.",
					HowToFix: "Enable the sandbox (`agents.defaults.sandbox.mode`) and keep `workspaceAccess` at `none` or `ro` unless the agent genuinely needs to write.",
				},
				{
					ID: "agent.control-ui-insecure", Key: "gateway.controlUi.allowInsecureAuth", Bad: []string{"true"},
					Good:     []any{false},
					Sev:      model.SeverityHigh,
					Title:    "Agent control UI has its auth safeguards disabled",
					Desc:     "The control UI drives the agent. With its authentication safeguards switched off, anyone who can reach the UI — including anything running locally on this host — can operate the agent.",
					HowToFix: "Remove `gateway.controlUi.allowInsecureAuth` (and `dangerouslyDisableDeviceAuth`) from the config and reach the UI over an SSH tunnel or a tailnet instead.",
				},
				{
					ID: "agent.control-ui-insecure", Key: "gateway.controlUi.dangerouslyDisableDeviceAuth", Bad: []string{"true"},
					Good:     []any{false},
					Sev:      model.SeverityHigh,
					Title:    "Agent control UI has its auth safeguards disabled",
					Desc:     "Device-identity checks are what stop an unknown client from pairing with the gateway. Disabled, any client that reaches the UI can act as an approved device.",
					HowToFix: "Remove `gateway.controlUi.dangerouslyDisableDeviceAuth` from the config and reach the UI over an SSH tunnel or a tailnet instead.",
				},
				{
					ID: "agent.ssrf-private-network", Key: "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", Bad: []string{"true"},
					Good:     []any{false},
					Sev:      model.SeverityMedium,
					Title:    "Agent browser may reach private network addresses",
					Desc:     "The agent's browser is permitted to fetch private and link-local addresses, so a page it visits can steer it into your LAN or a cloud metadata endpoint and read back the response — a server-side request forgery with an LLM driving it.",
					HowToFix: "Remove `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` so the default private-network block applies.",
				},
			},
		},
		{
			Name:    "hermes",
			Display: "Hermes Agent",
			Markers: []string{".hermes"},
			Config:  ".hermes/config.yaml",
			Format:  FormatYAML,
			EnvFile: ".hermes/.env",
			EnvOverrides: map[string]string{
				"dashboard.host":          "HERMES_DASHBOARD_HOST",
				"dashboard.auth.username": "HERMES_DASHBOARD_BASIC_AUTH_USERNAME",
			},
			Modes: []ModeRule{
				{Rel: ".hermes/config.yaml", Max: 0o600},
				{Rel: ".hermes/.env", Max: 0o600, Secret: true},
			},
			Gateway: GatewayDesc{
				DefaultPort: 9119,
				BindKey:     "dashboard.host",
				// Left empty on purpose: the dashboard binds 0.0.0.0 in the
				// container image but the native default is not documented,
				// so an unset key means "ask ss", not "assume exposed".
				BindDefault:  "",
				LoopbackOnly: []string{"127.0.0.1", "localhost", "::1"},
				AuthKey:      "dashboard.auth.username",
				// Hermes' auth gate is mandatory on a non-loopback bind, so an
				// unset username on an exposed dashboard is the open case.
				AuthDisabled: []string{""},
				ProcNames:    []string{"hermes", "uvicorn", "python", "python3"},
			},
		},
		{
			Name:    "goose",
			Display: "Goose",
			// `goose configure` creates this directory; the desktop app and
			// the CLI share it.
			Markers: []string{".config/goose"},
			Config:  ".config/goose/config.yaml",
			Format:  FormatYAML,
			Modes: []ModeRule{
				// The keyring fallback, and it is the case on a server:
				// with no desktop keyring service (or GOOSE_DISABLE_KEYRING
				// set) Goose writes API keys here in plain text, and sets
				// the file to 0600 itself — so anything looser was loosened
				// after the fact.
				{Rel: ".config/goose/secrets.yaml", Max: 0o600, Secret: true},
			},
			Gateway: GatewayDesc{
				// `goose web` takes --host and --port on its command line
				// (defaults 127.0.0.1 and 3000), and nothing about them is
				// written to config.yaml. goosed is the server the desktop
				// app starts; it binds loopback unless someone changed it.
				ProcNames:    []string{"goose", "goosed"},
				ListenerOnly: true,
			},
			Danger: []DangerRule{
				{
					ID: "agent.exec-unrestricted", Key: "GOOSE_MODE", Bad: []string{"auto"},
					// The documented default. A host where nobody chose a
					// mode is running the one that approves everything.
					Unset: "auto",
					Good:  []any{"approve", "smart_approve"},
					Sev:   model.SeverityHigh,
					Title: "Agent can run shell commands without approval",
					Desc: "Goose is in `auto` mode, which approves every tool call — shell commands and file edits included — without asking. It is also what Goose does when `GOOSE_MODE` is not set at all. " +
						"Anything that can steer the agent — a malicious web page it reads, a poisoned document, an instruction hidden in a repository it opens — can run commands as the user it runs as. " +
						"A `GOOSE_MODE` environment variable overrides this file and is not something hostveil can see.",
					HowToFix: "Set `GOOSE_MODE: approve` (ask before every tool call) or `GOOSE_MODE: smart_approve` (ask only for the ones judged risky) in ~/.config/goose/config.yaml, and make sure no `GOOSE_MODE=auto` is exported where Goose is started.",
				},
			},
		},
	}
}
