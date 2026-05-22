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
func MinimalAdapterFix(findings []domain.Finding) []FixAction {
	var actions []FixAction
	for _, f := range findings {
		actions = append(actions, adapterFixForFinding(f)...)
	}
	return actions
}

// MinimalHostFix returns host edit / shell command actions for applicable findings.
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

	// Generate text-based compose edit FixActions from findings
	// so that Apply() can actually modify the YAML file.
	if len(plan.AutoApplied) > 0 || len(plan.ReviewNeeded) > 0 {
		data, err := os.ReadFile(e.ComposeFile)
		if err == nil {
			content := string(data)
			for svc, findings := range byService {
				// Process auto-remediation findings first, then review-remediation findings.
				// This ensures auto actions' Content is findable in the original file when
				// Apply() applies auto-only actions in order.
				for _, rem := range []domain.RemediationKind{domain.RemediationAuto, domain.RemediationReview} {
					for _, f := range findings {
						if f.Source != domain.SourceNativeCompose {
							continue
						}
						if !f.IsFixable() {
							continue
						}
						if f.Remediation != rem {
							continue
						}
						snippet := extractServiceSnippet(content, svc, 5)
						if snippet == "" {
							continue
						}
						updated := applySnippetFix(snippet, f.ID)
						if updated != snippet {
							cmd := "auto"
							if f.Remediation == domain.RemediationReview {
								cmd = "review"
							}
							plan.Actions = append(plan.Actions, FixAction{
								Type:    ActionComposeEdit,
								Service: svc,
								Summary: f.Title,
								Content: snippet,
								Diff:    updated,
								Command: cmd,
							})
							// Update content for subsequent fix actions on the same service
							content = strings.Replace(content, snippet, updated, 1)
							snippet = extractServiceSnippet(content, svc, 5)
						}
					}
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

	// Apply compose edits (auto-fix only)
	content := string(data)
	for _, a := range plan.Actions {
		if a.Type == ActionComposeEdit && a.Command == "auto" {
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
	img := svcConfig.Image

	// Handle images with explicit :latest tag
	if strings.HasSuffix(img, ":latest") {
		svcConfig.Image = strings.TrimSuffix(img, ":latest") + ":stable"
		cf.Services[svc] = svcConfig
	} else if !strings.Contains(img, ":") {
		// No tag at all — add :stable
		svcConfig.Image = img + ":stable"
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
	diff := previewSnippetDiff(snippet, finding)

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Service: %s\n", svc))
	b.WriteString(fmt.Sprintf("Fix: %s\n\n", proposal.Summary))
	if diff != "" {
		b.WriteString("--- proposed diff ---\n")
		b.WriteString(diff)
		b.WriteString("\n---\n")
	} else if snippet != "" {
		b.WriteString("--- current context ---\n")
		b.WriteString(prefixLines(snippet, "  "))
		b.WriteString("\n---\n")
	}
	b.WriteString(fmt.Sprintf("Summary: %s\n", proposal.Summary))
	if proposal.Remediation == "auto" {
		b.WriteString("Status: Can be applied automatically\n")
	} else {
		b.WriteString("Status: Manual review recommended\n")
	}
	return b.String()
}

func previewSnippetDiff(snippet string, finding domain.Finding) string {
	if snippet == "" {
		return ""
	}
	updated := snippet
	switch finding.ID {
	case "exposure.public_binding":
		updated = addLoopbackBinding(snippet)
	case "runtime.no_new_privileges_disabled":
		updated = addServiceLine(snippet, "    security_opt:\n      - no-new-privileges:true")
	case "runtime.writable_rootfs":
		updated = addServiceLine(snippet, "    read_only: true")
	case "network.default_bridge_used":
		updated = addServiceLine(snippet, "    networks:\n      - hostveil")
	case "service.vaultwarden.insecure_domain":
		updated = strings.ReplaceAll(snippet, "http://", "https://")
	}
	if updated == snippet {
		return ""
	}
	return simpleLineDiff(snippet, updated)
}

func addLoopbackBinding(snippet string) string {
	lines := strings.Split(snippet, "\n")
	inPorts := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track whether we're inside a ports: section
		if strings.TrimRight(line, " ") == "    ports:" || strings.TrimRight(line, " ") == "  ports:" {
			inPorts = true
			continue
		}
		// If we were in ports and hit a non-empty line with less indentation, we've left ports
		if inPorts && trimmed != "" {
			indent := len(line) - len(strings.TrimLeft(line, " "))
			if indent < 6 {
				inPorts = false
			}
		}
		if !inPorts {
			continue
		}

		if !strings.HasPrefix(trimmed, "-") || strings.Contains(trimmed, "127.0.0.1:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		quote := ""
		if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			quote = `"`
			value = strings.Trim(value, `"`)
		}
		if strings.Count(value, ":") == 1 {
			updated := "127.0.0.1:" + value
			lines[i] = strings.Replace(line, strings.TrimSpace(strings.TrimPrefix(trimmed, "-")), quote+updated+quote, 1)
		}
	}
	return strings.Join(lines, "\n")
}

func addServiceLine(snippet, addition string) string {
	lines := strings.Split(snippet, "\n")
	insertAt := len(lines)
	serviceStart := -1
	for i := range lines {
		trimmed := strings.TrimSpace(lines[i])
		indent := len(lines[i]) - len(strings.TrimLeft(lines[i], " "))
		if serviceStart < 0 && indent == 2 && strings.HasSuffix(trimmed, ":") {
			serviceStart = i
			continue
		}
		if serviceStart >= 0 && i > serviceStart && indent <= 2 && trimmed != "" {
			insertAt = i
			break
		}
	}
	lines = append(lines[:insertAt], append(strings.Split(addition, "\n"), lines[insertAt:]...)...)
	return strings.Join(lines, "\n")
}

func simpleLineDiff(before, after string) string {
	oldLines := strings.Split(before, "\n")
	newLines := strings.Split(after, "\n")
	var b strings.Builder
	max := len(oldLines)
	if len(newLines) > max {
		max = len(newLines)
	}
	for i := 0; i < max; i++ {
		var oldLine, newLine string
		if i < len(oldLines) {
			oldLine = oldLines[i]
		}
		if i < len(newLines) {
			newLine = newLines[i]
		}
		switch {
		case i >= len(oldLines):
			b.WriteString("+ " + newLine + "\n")
		case i >= len(newLines):
			b.WriteString("- " + oldLine + "\n")
		case oldLine != newLine:
			b.WriteString("- " + oldLine + "\n")
			b.WriteString("+ " + newLine + "\n")
		default:
			b.WriteString("  " + oldLine + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func prefixLines(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

// PreviewAnyFinding returns a fix preview for any finding type.
// Dispatches to the appropriate preview based on finding source.
func PreviewAnyFinding(finding domain.Finding, composeFile string, allFindings []domain.Finding) string {
	switch finding.Source {
	case domain.SourceNativeCompose:
		if composeFile == "" {
			return "No compose file available for fix preview."
		}
		engine := NewEngine(composeFile, allFindings)
		return engine.PreviewFinding(finding)
	case domain.SourceNativeHost:
		return formatHostFixPreview(finding)
	default:
		return formatAdapterFixPreview(finding)
	}
}

func formatHostFixPreview(finding domain.Finding) string {
	actions := hostEditsForFinding(finding.ID, finding.Service)
	if len(actions) == 0 {
		return "No automated host fix available for this finding."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Fix for: %s\n", finding.ID))
	b.WriteString(fmt.Sprintf("Service: %s\n\n", finding.Service))

	for _, a := range actions {
		switch a.Type {
		case ActionHostEdit:
			b.WriteString("─── Host Edit ───\n")
			b.WriteString(fmt.Sprintf("File: %s\n", a.Path))
			b.WriteString(fmt.Sprintf("Change: %s\n", a.Summary))
			if a.Content != "" || a.Diff != "" {
				b.WriteString(fmt.Sprintf("  - %s\n", a.Content))
				b.WriteString(fmt.Sprintf("  + %s\n", a.Diff))
			}
			b.WriteString("\n")
		case ActionShellCommand:
			b.WriteString("─── Shell Command ───\n")
			b.WriteString(fmt.Sprintf("$ %s\n", a.Command))
			b.WriteString(fmt.Sprintf("Purpose: %s\n", a.Summary))
			if a.Rollback != "" {
				b.WriteString(fmt.Sprintf("Rollback: %s\n", a.Rollback))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("Status: Manual review recommended before applying\n")
	return b.String()
}

func formatAdapterFixPreview(finding domain.Finding) string {
	actions := adapterFixForFinding(finding)
	if len(actions) == 0 {
		return "No automated fix available for this adapter finding."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Fix for: %s\n", finding.ID))
	b.WriteString(fmt.Sprintf("Service: %s\n\n", finding.Service))

	for _, a := range actions {
		switch a.Type {
		case ActionShellCommand:
			b.WriteString("─── Shell Command ───\n")
			b.WriteString(fmt.Sprintf("$ %s\n", a.Command))
			b.WriteString(fmt.Sprintf("Purpose: %s\n", a.Summary))
			if a.Rollback != "" {
				b.WriteString(fmt.Sprintf("Rollback: %s\n", a.Rollback))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("Status: Manual review recommended\n")
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

// applySnippetFix applies a text fix for a specific finding ID to a YAML snippet.
// Returns the modified snippet or the original if no fix applies.
func applySnippetFix(snippet string, findingID string) string {
	switch findingID {
	case "exposure.public_binding":
		return addLoopbackBinding(snippet)
	case "runtime.no_new_privileges_disabled":
		return addServiceLine(snippet, "    security_opt:\n      - no-new-privileges:true")
	case "runtime.writable_rootfs":
		return addServiceLine(snippet, "    read_only: true")
	case "network.default_bridge_used":
		return addServiceLine(snippet, "    networks:\n      - hostveil")
	case "updates.latest_tag":
		return addServiceLine(snippet, "    # TODO: pin image version tag")
	case "service.vaultwarden.insecure_domain":
		return strings.ReplaceAll(snippet, "http://", "https://")
	}
	return snippet
}
