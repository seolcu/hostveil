package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/history"
)

type dryRunAction struct {
	label       string
	actionType  string
	warning     string
	diffPreview string
}

type fixResultMsg struct{ result fix.FixResult }
type fixProgressMsg struct {
	current, total int
	label          string
}
type fixBatchResultMsg struct{ success, fail, skipped int }

func isBatchFixableFinding(f domain.Finding) bool {
	return !f.Fixed && f.Remediation != domain.RemediationUnavailable && f.Remediation != domain.RemediationManual
}

func (m *model) toggleSelection() {
	visible := m.visibleFindings()
	idx := m.table.Cursor()
	if idx < 0 && len(visible) > 0 {
		idx = 0
		m.table.SetCursor(0)
	}
	if idx < 0 || idx >= len(visible) {
		return
	}
	if !isBatchFixableFinding(visible[idx]) {
		return
	}
	id := visible[idx].ID
	if m.selectedSet[id] {
		delete(m.selectedSet, id)
	} else {
		m.selectedSet[id] = true
	}
}

func (m *model) runBatchFix() (tea.Model, tea.Cmd) {
	if m.fixReg == nil {
		m.toast = "Fix engine not available"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}
	visible := m.visibleFindings()
	var toFix []domain.Finding
	for _, f := range visible {
		if m.selectedSet[f.ID] && isBatchFixableFinding(f) {
			toFix = append(toFix, f)
		}
	}
	if len(toFix) == 0 {
		m.toast = "No findings selected"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}

	m.fixProgress = 0
	m.fixProgressTotal = len(toFix)
	m.fixProgressLabel = ""
	m.modal = modalFixProgress

	reg := m.fixReg
	total := len(toFix)
	send := m.send
	go func() {
		success, fail, skipped := 0, 0, 0
		for i, finding := range toFix {
			if send != nil {
				send(fixProgressMsg{current: i + 1, total: total, label: finding.ID})
			}
			f := reg.Lookup(finding.ID)
			if f == nil {
				fail++
				continue
			}
			if len(f.Actions) > 1 {
				skipped++
				continue
			}
			result := history.ApplyWithCheckpoint(f, &finding, 0)
			if result.Success {
				success++
				m.live.MarkFixed(finding.ID, finding.Service)
				if finding.Service != "" && reg.HasExactEntry(finding.ID) {
					m.live.MarkRelatedFixed(finding.ID, finding.Service, func(candidateID string) bool {
						return reg.Lookup(candidateID) == f
					})
				}
			} else {
				fail++
			}
		}
		if send != nil {
			send(fixBatchResultMsg{success: success, fail: fail, skipped: skipped})
		}
	}()
	return m, tickCmd()
}

func (m model) runFix() (tea.Model, tea.Cmd) {
	if m.fixReg == nil {
		m.toast = "Fix engine not available"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}
	visible := m.visibleFindings()
	if len(visible) == 0 {
		return m, nil
	}
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(visible) {
		return m, nil
	}
	f := m.fixReg.Lookup(visible[idx].ID)
	if f == nil {
		m.toast = "No fix available for this finding"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}

	if f.Class() == domain.RemediationManual {
		m.toast = "This fix requires manual review. See guidance in the detail panel."
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}
	if f.Class() == domain.RemediationUnavailable {
		m.toast = "No automatic fix available for this finding."
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	}
	m.fixTarget = f
	m.fixActionIdx = 0

	finding := visible[idx]
	m.dryRunActions = make([]dryRunAction, len(f.Actions))
	for i, a := range f.Actions {
		info := dryRunAction{
			label:      a.Label,
			actionType: a.Type.String(),
			warning:    a.Warning,
		}
		if a.Type == fix.ActionEdit {
			diff, _ := fix.SimulateDiff(fix.Context{Finding: &finding}, a)
			if diff != "" {
				info.diffPreview = diff
			}
		}
		m.dryRunActions[i] = info
	}
	m.dryRunApplyIdx = 0

	if len(f.Actions) > 1 {
		m.modal = modalDryRun
		return m, nil
	}
	m.modal = modalDryRun
	return m, nil
}

func (m model) applyFix() (tea.Model, tea.Cmd) {
	f := m.fixTarget
	if f == nil || m.fixActionIdx >= len(f.Actions) {
		return m, nil
	}
	visible := m.visibleFindings()
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(visible) {
		return m, nil
	}
	finding := visible[idx]
	return m, func() tea.Msg {
		result := history.ApplyWithCheckpoint(f, &finding, m.fixActionIdx)
		return fixResultMsg{result: result}
	}
}

type exportFormat struct {
	label string
	ext   string
}

var exportFormats = []exportFormat{
	{label: "JSON (full data)", ext: "json"},
	{label: "CSV (spreadsheet)", ext: "csv"},
	{label: "AI brief (Markdown)", ext: "md"},
}

func (m *model) exportReport() {
	snap := m.live.Snapshot()
	ts := time.Now().Format("2006-01-02_150405")

	idx := m.exportIdx
	if idx < 0 || idx >= len(exportFormats) {
		idx = 0
	}
	format := exportFormats[idx]
	name := "hostveil-report"
	if format.ext == "md" {
		name = "hostveil-ai-brief"
	}
	filename := fmt.Sprintf("%s-%s", name, ts)

	path := filename + "." + format.ext
	var content string
	switch format.ext {
	case "json":
		data, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			m.toast = "Export failed: " + err.Error()
			m.toastUntil = time.Now().Add(5 * time.Second)
			return
		}
		content = string(data)
	case "csv":
		var buf strings.Builder
		buf.WriteString("ID,Severity,Source,Service,Title,Description,Remediation,Fixed\n")
		for _, f := range snap.Findings {
			buf.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%v\n",
				domain.EscapeCSV(f.ID), f.Severity.String(), f.Source.String(), domain.EscapeCSV(f.Service),
				domain.EscapeCSV(f.Title), domain.EscapeCSV(f.Description), f.Remediation.String(), f.Fixed))
		}
		content = buf.String()
	case "md":
		content = domain.RenderAIBrief(snap)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fallback := "/tmp/" + fmt.Sprintf("%s.%s", strings.TrimPrefix(filename, name+"-"), format.ext)
		if err2 := os.WriteFile(fallback, []byte(content), 0644); err2 != nil {
			m.fixResult = "✗ Export failed\n\nPrimary: " + err.Error() + "\nFallback (/tmp): " + err2.Error()
			m.modal = modalFixResult
			return
		}
		m.toast = "Exported to " + fallback + " (primary path failed)"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return
	}
	m.toast = "Exported to " + path
	m.toastUntil = time.Now().Add(5 * time.Second)
}
