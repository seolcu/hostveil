package main

import (
	"os"

	"github.com/seolcu/hostveil/internal/ai"
	"github.com/seolcu/hostveil/internal/check"
	accountscheck "github.com/seolcu/hostveil/internal/check/accounts"
	agentcheck "github.com/seolcu/hostveil/internal/check/agent"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	cvecheck "github.com/seolcu/hostveil/internal/check/cve"
	filepermscheck "github.com/seolcu/hostveil/internal/check/fileperms"
	firewallcheck "github.com/seolcu/hostveil/internal/check/firewall"
	portscheck "github.com/seolcu/hostveil/internal/check/ports"
	sshcheck "github.com/seolcu/hostveil/internal/check/ssh"
	sysctlcheck "github.com/seolcu/hostveil/internal/check/sysctl"
	updatescheck "github.com/seolcu/hostveil/internal/check/updates"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/platform"
)

// buildEngine constructs the shared engine with every checker and the
// default fix registry. All subcommands go through this one engine, so
// scan, fix, and rollback share exactly one implementation.
func buildEngine() *core.Engine { return buildEngineWithAI(false) }

// buildEngineWithAI is buildEngine with the optional, advisory-only local
// AI provider (Ollama) wired in when useAI is set.
func buildEngineWithAI(useAI bool) *core.Engine {
	cfg := core.Config{
		Registry: check.NewRegistry(
			composecheck.New(),
			sshcheck.New(),
			firewallcheck.New(),
			updatescheck.New(),
			cvecheck.New(),
			portscheck.New(),
			accountscheck.New(),
			filepermscheck.New(),
			agentcheck.New(),
			sysctlcheck.New(),
		),
		Fixes:  fix.Default(),
		Runner: debugRunner(),
	}
	if useAI {
		cfg.AI = ai.NewOllama()
	}
	return core.New(cfg)
}

// debugRunner returns the command runner the engine should use: the plain
// one, or a tracing wrapper when HOSTVEIL_DEBUG is set.
//
// An environment variable rather than a flag, because it has to work for
// every command without threading a flag through six of them — and because
// the thing you tell someone in a bug report is one line they can paste:
//
//	HOSTVEIL_DEBUG=1 hostveil scan
//
// The trace goes to stderr, so `--json` and every redirect produce exactly
// the bytes they did before. Returning nil leaves core.New to pick its own
// default, which keeps the untraced path identical to what it was.
func debugRunner() platform.CommandRunner {
	if os.Getenv("HOSTVEIL_DEBUG") == "" {
		return nil
	}
	return platform.NewTraceRunner(platform.DefaultRunner{}, os.Stderr)
}
