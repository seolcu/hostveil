package main

import (
	"os"

	"github.com/seolcu/hostveil/internal/ai"
	"github.com/seolcu/hostveil/internal/check"
	accountscheck "github.com/seolcu/hostveil/internal/check/accounts"
	agentcheck "github.com/seolcu/hostveil/internal/check/agent"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	cvecheck "github.com/seolcu/hostveil/internal/check/cve"
	dockerdcheck "github.com/seolcu/hostveil/internal/check/dockerd"
	filepermscheck "github.com/seolcu/hostveil/internal/check/fileperms"
	firewallcheck "github.com/seolcu/hostveil/internal/check/firewall"
	portscheck "github.com/seolcu/hostveil/internal/check/ports"
	sshcheck "github.com/seolcu/hostveil/internal/check/ssh"
	sysctlcheck "github.com/seolcu/hostveil/internal/check/sysctl"
	systemdcheck "github.com/seolcu/hostveil/internal/check/systemd"
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
		Registry: buildRegistry(),
		Fixes:    fix.Default(),
		Runner:   debugRunner(),
	}
	if useAI {
		cfg.AI = ai.NewOllama()
	}
	return core.New(cfg)
}

// buildRegistry lists every checker, in scan order.
//
// This order is load-bearing: Registry.Run writes its results by registry
// index, so this is what orders Report.Domains and therefore the CLI's
// per-domain status block. It is the third copy of the domain order — the
// other two, AllSources and the scoring axes, were merged into one table
// in internal/model and can no longer disagree with each other.
// TestCheckerRegistrationMatchesSourceOrder holds this one to that table.
func buildRegistry() *check.Registry {
	return check.NewRegistry(
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
		dockerdcheck.New(),
		systemdcheck.New(),
	)
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
