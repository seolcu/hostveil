package main

import (
	"github.com/seolcu/hostveil/internal/ai"
	"github.com/seolcu/hostveil/internal/check"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	cvecheck "github.com/seolcu/hostveil/internal/check/cve"
	firewallcheck "github.com/seolcu/hostveil/internal/check/firewall"
	sshcheck "github.com/seolcu/hostveil/internal/check/ssh"
	updatescheck "github.com/seolcu/hostveil/internal/check/updates"
	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/fix"
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
		),
		Fixes: fix.Default(),
	}
	if useAI {
		cfg.AI = ai.NewOllama()
	}
	return core.New(cfg)
}
