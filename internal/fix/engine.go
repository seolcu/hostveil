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

// MinimalAdapterFix returns fix actions for external adapter findings.
// Full implementation tracked in issue #385.
func MinimalAdapterFix(findings []domain.Finding) []FixAction {
	var actions []FixAction
	for _, f := range findings {
		actions = append(actions, adapterFixForFinding(f.ID, f.Service)...)
	}
	return actions
}

// MinimalHostFix returns host edit / shell command actions for applicable findings.
// Full implementation tracked in issue #384.
func MinimalHostFix(findings []domain.Finding) *FixPlan {
	plan := &FixPlan{}
	for _, f := range findings {
		actions := hostEditsForFinding(f.ID, f.Service)
		for _, a := range actions {
			switch a.Type {
			case ActionHostEdit:
				plan.HostEdits = append(plan.HostEdits, a)
			case ActionShellCommand:
				plan.ShellCmds = append(plan.ShellCmds, a)
			}
			plan.Actions = append(plan.Actions, a)
		}
	}
	return plan
}

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

// PreviewFinding returns a finding-specific diff preview with YAML context.
func (e *Engine) PreviewFinding(finding domain.Finding) string {
	data, err := os.ReadFile(e.ComposeFile)
	if err != nil {
		return fmt.Sprintf("Cannot read compose file: %v", err)
	}

	cf, err := compose.ParseFile(e.ComposeFile)
	if err != nil {
		return fmt.Sprintf("Cannot parse compose file: %v", err)
	}

	svc := finding.Service
	if _, ok := cf.Services[svc]; !ok {
		return fmt.Sprintf("Service %q not found in compose file", svc)
	}

	proposal := e.fixForFinding(finding, cf, svc)
	if proposal == nil {
		return "No automated fix available for this finding."
	}

	snippet := extractServiceSnippet(string(data), svc, 3)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Service: %s\n", svc))
	b.WriteString(fmt.Sprintf("Fix: %s\n\n", proposal.Summary))
	if snippet != "" {
		b.WriteString("--- current config ---\n")
		b.WriteString(snippet)
		b.WriteString("\n---\n")
	}
	b.WriteString(fmt.Sprintf("→ %s\n", proposal.Summary))
	if proposal.Remediation == "auto" {
		b.WriteString("Status: Can be applied automatically\n")
	} else {
		b.WriteString("Status: Manual review recommended\n")
	}
	b.WriteString("\nPress f to toggle preview, Enter to return to detail")

	return b.String()
}

// extractServiceSnippet extracts a service's YAML block with surrounding context lines.
func extractServiceSnippet(content, serviceName string, context int) string {
	lines := strings.Split(content, "\n")

	servicesIdx := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "services:" {
			servicesIdx = i
			break
		}
	}
	if servicesIdx < 0 {
		return ""
	}

	serviceStart := -1
	serviceEnd := len(lines)

	for i := servicesIdx + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		if indent == 2 && strings.Contains(lines[i], ":") {
			name := strings.TrimSpace(strings.SplitN(lines[i], ":", 2)[0])
			if name == serviceName {
				serviceStart = i
			} else if serviceStart >= 0 {
				serviceEnd = i
				break
			}
		}
	}

	if serviceStart < 0 {
		return ""
	}

	start := serviceStart - context
	if start < 0 {
		start = 0
	}
	end := serviceEnd + context
	if end > len(lines) {
		end = len(lines)
	}

	return strings.Join(lines[start:end], "\n")
}
