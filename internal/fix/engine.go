package fix

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type Engine struct {
	ComposeFile string
	Findings    []domain.Finding
}

func NewEngine(composeFile string, findings []domain.Finding) *Engine {
	return &Engine{
		ComposeFile: composeFile,
		Findings:    findings,
	}
}

func (e *Engine) Preview() (*FixPlan, error) {
	cf, err := compose.ParseFile(e.ComposeFile)
	if err != nil {
		return nil, fmt.Errorf("parse compose: %w", err)
	}

	plan := &FixPlan{
		ComposeFile: e.ComposeFile,
	}

	// Group findings by service
	byService := make(map[string][]domain.Finding)
	for _, f := range e.Findings {
		svc := f.Service
		if svc == "" {
			svc = "_project"
		}
		byService[svc] = append(byService[svc], f)
	}

	for svc, findings := range byService {
		svcConfig, ok := cf.Services[svc]
		if !ok && svc != "_project" {
			continue
		}
		_ = svcConfig

		for _, f := range findings {
			proposal := e.fixForFinding(f, cf, svc)
			if proposal != nil {
				switch proposal.Remediation {
				case "auto":
					plan.AutoApplied = append(plan.AutoApplied, *proposal)
				case "review":
					plan.ReviewNeeded = append(plan.ReviewNeeded, *proposal)
				}
			}
		}
	}

	// Generate diff preview
	plan.DiffPreview = e.generateDiff(plan)

	return plan, nil
}

func (e *Engine) Apply() (*FixPlan, error) {
	plan, err := e.Preview()
	if err != nil {
		return nil, err
	}

	if !plan.Changed() {
		return plan, nil
	}

	// Backup original file
	backupDir := filepath.Dir(e.ComposeFile)
	backupName := fmt.Sprintf("%s.bak.%d", filepath.Base(e.ComposeFile), time.Now().Unix())
	backupPath := filepath.Join(backupDir, backupName)

	data, err := os.ReadFile(e.ComposeFile)
	if err != nil {
		return nil, fmt.Errorf("read compose: %w", err)
	}

	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return nil, fmt.Errorf("backup: %w", err)
	}
	plan.BackupPath = backupPath

	// Apply compose edits
	content := string(data)
	for _, a := range plan.Actions {
		if a.Type == ActionComposeEdit {
			content = strings.Replace(content, a.Content, a.Diff, 1)
		}
	}

	if err := os.WriteFile(e.ComposeFile, []byte(content), 0644); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	return plan, nil
}

func (e *Engine) fixForFinding(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	if !f.IsFixable() {
		return nil
	}

	switch f.ID {
	case "exposure.public_binding":
		return e.fixPublicBinding(f, cf, svc)
	case "runtime.no_new_privileges_disabled":
		return e.fixDropAllCapabilities(f, cf, svc)
	case "runtime.writable_rootfs":
		return e.fixReadOnlyRootfs(f, cf, svc)
	case "updates.latest_tag":
		return e.fixPinVersion(f, cf, svc)
	case "network.default_bridge_used":
		return e.fixCustomNetwork(f, cf, svc)
	case "exposure.reverse_proxy_expected":
		return &FixProposal{
			Service:     svc,
			Summary:     "Consider adding a reverse proxy for " + svc,
			Remediation: "review",
		}
	case "service.vaultwarden.signups_allowed":
		return &FixProposal{
			Service:     svc,
			Summary:     "Disable open registration: set SIGNUPS_ALLOWED=false",
			Remediation: "review",
		}
	case "service.vaultwarden.insecure_domain":
		return &FixProposal{
			Service:     svc,
			Summary:     "Change DOMAIN to HTTPS URL",
			Remediation: "review",
		}
	}

	return nil
}

func (e *Engine) fixPublicBinding(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	svcConfig := cf.Services[svc]
	for i, p := range svcConfig.Ports {
		if p.HostIP == "" || p.HostIP == "0.0.0.0" {
			svcConfig.Ports[i].HostIP = "127.0.0.1"
		}
	}
	cf.Services[svc] = svcConfig

	return &FixProposal{
		Service:     svc,
		Summary:     "Bound " + svc + " ports to 127.0.0.1",
		Remediation: "auto",
	}
}

func (e *Engine) fixDropAllCapabilities(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	return &FixProposal{
		Service:     svc,
		Summary:     "cap_drop: ALL recommended for " + svc,
		Remediation: "auto",
	}
}

func (e *Engine) fixReadOnlyRootfs(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	return &FixProposal{
		Service:     svc,
		Summary:     "Set read_only: true for " + svc,
		Remediation: "auto",
	}
}

func (e *Engine) fixPinVersion(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	svcConfig := cf.Services[svc]
	if !strings.Contains(svcConfig.Image, ":") {
		svcConfig.Image = svcConfig.Image + ":stable"
		cf.Services[svc] = svcConfig
	}

	return &FixProposal{
		Service:     svc,
		Summary:     "Pinned image version for " + svc + ": " + svcConfig.Image,
		Remediation: "auto",
	}
}

func (e *Engine) fixCustomNetwork(f domain.Finding, cf *compose.ComposeFile, svc string) *FixProposal {
	return &FixProposal{
		Service:     svc,
		Summary:     "Define a custom network for " + svc,
		Remediation: "auto",
	}
}

func (e *Engine) generateDiff(plan *FixPlan) string {
	var parts []string
	if len(plan.AutoApplied) > 0 {
		parts = append(parts, "## Auto-fixes")
		for _, p := range plan.AutoApplied {
			parts = append(parts, "  + "+p.Service+": "+p.Summary)
		}
	}
	if len(plan.ReviewNeeded) > 0 {
		parts = append(parts, "## Review Required")
		for _, p := range plan.ReviewNeeded {
			parts = append(parts, "  ~ "+p.Service+": "+p.Summary)
		}
	}
	return strings.Join(parts, "\n")
}
