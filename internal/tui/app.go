// Package tui provides the Bubble Tea terminal user interface.
package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/scan"
)

var Version = "v2.3.0"

type paneMode int

const (
	paneList paneMode = iota
	paneDetail
)

type modalMode int

const (
	modalNone modalMode = iota
	modalHelp
	modalFilter
	modalFixAction
	modalFixConfirm
	modalFixResult
	modalFixProgress
	modalExport
)

type filterState struct {
	query       string
	severity    string
	source      string
	remediation string
	sortBy      string
	service     string
}

type model struct {
	live   *domain.ScanProgress
	snap   domain.Snapshot
	fixReg *fix.Registry
	send   func(tea.Msg)
	width  int
	height int

	phase  string
	snapOK bool

	// bubbles v2 components
	spinner   spinner.Model
	table     table.Model
	viewport  viewport.Model
	help      help.Model
	searchBox textinput.Model

	// UI state
	mode   paneMode
	filter filterState

	// modals
	modal modalMode

	// fix
	fixTarget    *fix.Fix
	fixActionIdx int
	fixResult    string

	// export
	exportIdx int

	// batch selection
	selectedSet map[string]bool

	// batch fix progress
	fixProgress      int
	fixProgressTotal int
	fixProgressLabel string

	// toast
	toast      string
	toastUntil time.Time

	// confirm reset
	confirmReset bool

	// cached render heights
	headerH  int
	metricsH int
}

type tickMsg struct{}
type fixResultMsg struct{ result fix.FixResult }
type fixProgressMsg struct{ current, total int; label string }
type fixBatchResultMsg struct{ success, fail, skipped int }

func NewApp(live *domain.ScanProgress, reg *fix.Registry) *model {
	s := spinner.New(spinner.WithSpinner(spinner.Dot))

	t := table.New(
		table.WithColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Source", Width: 6},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: 40},
			{Title: "Fix", Width: 11},
		}),
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(tableStyles(DefaultTheme())),
	)

	search := textinput.New()
	search.Placeholder = "Search findings..."
	search.CharLimit = 64

	vp := viewport.New()
	vp.SoftWrap = true

	return &model{
		live:        live,
		fixReg:      reg,
		spinner:     s,
		table:       t,
		viewport:    vp,
		help:        help.New(),
		searchBox:   search,
		selectedSet: make(map[string]bool),
		filter: filterState{
			severity:    "all",
			source:      "all",
			remediation: "all",
			sortBy:      "severity",
			service:     "all",
		},
		phase: "loading",
	}
}

func (m *model) SetProgram(send func(tea.Msg)) {
	m.send = send
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), func() tea.Msg { return m.spinner.Tick() })
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.snap = m.live.Snapshot()
		m.snapOK = true
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetWidth(m.listTableWidth())
		m.viewport.SetWidth(max(20, m.detailWidth()-8))
		m.table.SetHeight(m.listHeight())
		m.viewport.SetHeight(m.detailHeight())
		if m.phase == "ready" {
			m.rebuildTable()
		}
		return m, nil

	case tickMsg:
		if m.phase == "loading" {
			m.snap = m.live.Snapshot()
			m.snapOK = true
			if m.snap.Phase == "complete" {
				m.phase = "ready"
				m.toast = ""
				m.toastUntil = time.Time{}
				if m.width > 0 && m.height > 0 {
					m.rebuildTable()
				}
			}
			return m, tickCmd()
		}
		if m.toast != "" && !m.toastUntil.IsZero() && time.Now().After(m.toastUntil) {
			m.toast = ""
			m.toastUntil = time.Time{}
		}
		return m, tickCmd()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.phase == "loading" {
			return m, tea.Batch(cmd, func() tea.Msg { return m.spinner.Tick() })
		}
		return m, cmd

	case fixResultMsg:
		if msg.result.Success {
			visible := m.visibleFindings()
			idx := m.table.Cursor()
			if idx >= 0 && idx < len(visible) {
				id := visible[idx].ID
				for i := range m.snap.Findings {
					if m.snap.Findings[i].ID == id {
						m.snap.Findings[i].Fixed = true
						break
					}
				}
				m.live.MarkFixed(id)
			}
			m.fixResult = "✓ " + msg.result.Label
			if msg.result.Diff != "" {
				m.fixResult += "\n\n" + msg.result.Diff
			}
			m.rebuildTable()
		} else {
			m.fixResult = "✗ " + msg.result.Error
		}
		m.modal = modalFixResult
		return m, nil

	case fixProgressMsg:
		m.fixProgress = msg.current
		m.fixProgressTotal = msg.total
		m.fixProgressLabel = msg.label
		return m, nil

	case fixBatchResultMsg:
		m.modal = modalNone
		m.selectedSet = make(map[string]bool)
		m.rebuildTable()
		if msg.success > 0 || msg.fail > 0 || msg.skipped > 0 {
			parts := []string{fmt.Sprintf("Fixed %d", msg.success)}
			if msg.fail > 0 {
				parts = append(parts, fmt.Sprintf("%d failed", msg.fail))
			}
			if msg.skipped > 0 {
				parts = append(parts, fmt.Sprintf("%d skipped (multi-action)", msg.skipped))
			}
			m.toast = strings.Join(parts, ", ")
			m.toastUntil = time.Now().Add(5 * time.Second)
		}
		return m, nil

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.phase == "loading" {
			if msg.String() == "q" {
				return m, tea.Quit
			}
			return m, nil
		}
		if !m.snapOK {
			m.snap = m.live.Snapshot()
			m.snapOK = true
		}
		if m.modal != modalNone {
			return m.updateModal(msg)
		}
		return m.updateMain(msg)

	case tea.MouseMsg:
		if m.phase == "loading" || m.modal != modalNone {
			return m, nil
		}
		if !m.snapOK {
			m.snap = m.live.Snapshot()
			m.snapOK = true
		}
		mouse := msg.Mouse()
		if m.width <= 0 || m.height <= 0 {
			return m, nil
		}
		headerH := lipgloss.Height(m.renderHeader())
		metricsH := lipgloss.Height(m.renderMetrics())
		if mouse.Y < headerH+metricsH {
			return m, nil
		}
		target := m.panelAt(mouse.X)
		listStartY := headerH + metricsH
		headH := 5
		tableStartY := listStartY + 1 + headH
		switch mouse.Button {
		case tea.MouseLeft:
			if target == paneList {
				if !m.inlineDetail() && m.mode == paneDetail {
					m.mode = paneList
				} else if m.mode != paneList {
					m.mode = paneList
				}
				row := mouse.Y - tableStartY
				if row >= 0 && row < m.listHeight() {
					m.table.SetCursor(row)
					if m.inlineDetail() {
						m.updateDetailViewport()
					}
				}
			} else if target == paneDetail {
				if !m.inlineDetail() {
					m.mode = paneDetail
					m.updateDetailViewport()
				} else {
					m.mode = paneDetail
					m.updateDetailViewport()
				}
			}
		case tea.MouseWheelUp:
			if target == paneDetail {
				m.viewport.ScrollUp(3)
			} else {
				m.table, _ = m.table.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyUp}))
			}
		case tea.MouseWheelDown:
			if target == paneDetail {
				m.viewport.ScrollDown(3)
			} else {
				m.table, _ = m.table.Update(tea.KeyPressMsg(tea.Key{Code: tea.KeyDown}))
			}
		}
		if target == paneList && m.inlineDetail() {
			m.updateDetailViewport()
		}
		return m, nil
	}
	return m, nil
}

func (m model) updateMain(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()

	if m.confirmReset && keyStr != "R" {
		m.confirmReset = false
	}

	// Global shortcuts
	switch keyStr {
	case "q":
		if m.mode == paneDetail {
			m.mode = paneList
			m.updateDetailViewport()
			return m, nil
		}
		return m, tea.Quit
	case "?":
		m.modal = modalHelp
		return m, nil
	case "tab":
		if m.inlineDetail() {
			if m.mode == paneDetail {
				m.mode = paneList
			} else {
				m.mode = paneDetail
				m.updateDetailViewport()
			}
		}
		return m, nil
	case "/":
		m.modal = modalFilter
		m.searchBox.SetValue(m.filter.query)
		m.searchBox.Focus()
		return m, nil
	case "f":
		if len(m.selectedSet) > 0 {
			return m.runBatchFix()
		}
		return m.runFix()
	case "1":
		m.filter.severity = "critical"
		m.rebuildTable()
		return m, nil
	case "2":
		m.filter.severity = "high"
		m.rebuildTable()
		return m, nil
	case "3":
		m.filter.severity = "medium"
		m.rebuildTable()
		return m, nil
	case "4":
		m.filter.severity = "low"
		m.rebuildTable()
		return m, nil
	case "0":
		m.filter.severity = "all"
		m.rebuildTable()
		return m, nil
	case "s":
		m.cycleSourceFilter()
		m.rebuildTable()
		return m, nil
	case "r":
		m.cycleRemediationFilter()
		m.rebuildTable()
		return m, nil
	case "o":
		m.cycleSortOrder()
		m.rebuildTable()
		return m, nil
	case "v":
		m.cycleServiceFilter()
		m.rebuildTable()
		return m, nil
	case "R":
		if m.confirmReset {
			m.filter.query = ""
			m.filter.severity = "all"
			m.filter.source = "all"
			m.filter.remediation = "all"
			m.filter.service = "all"
			m.rebuildTable()
			m.toast = "Filters cleared"
			m.toastUntil = time.Now().Add(3 * time.Second)
			m.confirmReset = false
		} else {
			m.confirmReset = true
			m.toast = "Press R again to confirm reset"
			m.toastUntil = time.Now().Add(5 * time.Second)
		}
		return m, nil
	case "ctrl+r":
		m.live.Recalculate()
		m.snap = m.live.Snapshot()
		m.snapOK = true
		m.toast = "Score recalculated"
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m, nil
	case "ctrl+s":
		m = m.startRescan()
		return m, tickCmd()
	case "e":
		m.exportIdx = 0
		m.modal = modalExport
		return m, nil
	}

	// Detail mode: delegate to viewport for scrolling
	if m.mode == paneDetail {
		switch keyStr {
		case "esc", "h", "left":
			m.mode = paneList
			m.updateDetailViewport()
			return m, nil
		case "g":
			m.viewport.GotoTop()
			return m, nil
		case "G":
			m.viewport.GotoBottom()
			return m, nil
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}

	// List mode: delegate to table for navigation
	switch keyStr {
	case " ", "space":
		m.toggleSelection()
		cursor := m.table.Cursor()
		m.rebuildTable()
		m.table.SetCursor(cursor)
		return m, nil
	case "g":
		m.table.SetCursor(0)
		m.updateDetailViewport()
		return m, nil
	case "G":
		visible := m.visibleFindings()
		if len(visible) > 0 {
			m.table.SetCursor(len(visible) - 1)
			m.updateDetailViewport()
		}
		return m, nil
	case "enter", "l", "right":
		visible := m.visibleFindings()
		cursor := m.table.Cursor()
		if cursor >= 0 && cursor < len(visible) {
			m.mode = paneDetail
			m.updateDetailViewport()
		}
		return m, nil
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	if m.inlineDetail() {
		m.updateDetailViewport()
	}
	return m, cmd
}

func (m model) updateModal(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.modal {
	case modalHelp:
		switch msg.String() {
		case "q", "esc", "?", "enter":
			m.modal = modalNone
		}
	case modalFilter:
		switch msg.String() {
		case "esc":
			m.modal = modalNone
			m.searchBox.Blur()
			return m, nil
		case "enter":
			m.filter.query = m.searchBox.Value()
			m.modal = modalNone
			m.searchBox.Blur()
			m.rebuildTable()
			return m, nil
		}
		var cmd tea.Cmd
		m.searchBox, cmd = m.searchBox.Update(msg)
		return m, cmd
	case modalFixAction:
		switch msg.String() {
		case "up", "k":
			if m.fixActionIdx > 0 {
				m.fixActionIdx--
			}
		case "down", "j":
			if m.fixTarget != nil && m.fixActionIdx < len(m.fixTarget.Actions)-1 {
				m.fixActionIdx++
			}
		case "enter", "l":
			if m.fixTarget != nil && len(m.fixTarget.Actions) > 0 {
				if m.fixTarget.Actions[m.fixActionIdx].Warning != "" {
					m.modal = modalFixConfirm
				} else {
					m.modal = modalNone
					m.toast = "Applying fix..."
					m.toastUntil = time.Now().Add(5 * time.Second)
					m2, cmd := m.applyFix()
					return m2, cmd
				}
			}
		case "q", "esc":
			m.fixTarget = nil
			m.modal = modalNone
		}
	case modalFixConfirm:
		switch msg.String() {
		case "y", "Y":
			m.modal = modalNone
			m2, cmd := m.applyFix()
			return m2, cmd
		case "n", "N", "q", "esc":
			m.fixTarget = nil
			m.modal = modalNone
		}
	case modalFixResult:
		switch msg.String() {
		case "q", "esc", "enter":
			m.fixTarget = nil
			m.modal = modalNone
		}
	case modalFixProgress:
		return m, nil
	case modalExport:
		switch msg.String() {
		case "up", "k":
			m.exportIdx = 0
		case "down", "j":
			m.exportIdx = 1
		case "enter", "l":
			m.modal = modalNone
			m.exportReport()
		case "q", "esc":
			m.modal = modalNone
		}
	}
	return m, nil
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
	if visible[idx].Remediation == domain.RemediationUnavailable {
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
		if m.selectedSet[f.ID] {
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
			result := f.Run(fix.Context{
				Finding: &finding,
				Log:     func(s string, args ...interface{}) {},
			}, 0)
			if result.Success {
				success++
				m.live.MarkFixed(finding.ID)
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
	m.fixTarget = f
	m.fixActionIdx = 0

	if len(f.Actions) > 1 {
		m.modal = modalFixAction
		return m, nil
	}

	switch f.Class() {
	case domain.RemediationAuto:
		if f.Actions[0].Warning != "" {
			m.modal = modalFixConfirm
			return m, nil
		}
		m.toast = "Applying fix..."
		m.toastUntil = time.Now().Add(5 * time.Second)
		return m.applyFix()
	case domain.RemediationReview:
		m.toast = "Applying fix..."
		m.toastUntil = time.Now().Add(5 * time.Second)
		m.modal = modalFixConfirm
		return m, nil
	default:
		return m, nil
	}
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
		result := f.Run(fix.Context{
			Finding: &finding,
			Log:     func(s string, args ...interface{}) {},
		}, m.fixActionIdx)
		return fixResultMsg{result: result}
	}
}

func (m *model) exportReport() {
	snap := m.live.Snapshot()
	ts := time.Now().Format("2006-01-02_150405")
	filename := fmt.Sprintf("hostveil-report-%s", ts)

	var path, content string
	if m.exportIdx == 0 {
		path = filename + ".json"
		data, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			m.toast = "Export failed: " + err.Error()
			m.toastUntil = time.Now().Add(5 * time.Second)
			return
		}
		content = string(data)
	} else {
		path = filename + ".csv"
		var buf strings.Builder
		buf.WriteString("ID,Severity,Source,Service,Title,Remediation,Fixed\n")
		for _, f := range snap.Findings {
			buf.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%s,%v\n",
				domain.EscapeCSV(f.ID), f.Severity.String(), f.Source.String(), domain.EscapeCSV(f.Service),
				domain.EscapeCSV(f.Title), f.Remediation.String(), f.Fixed))
		}
		content = buf.String()
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fallback := "/tmp/" + fmt.Sprintf("%s.%s", strings.TrimPrefix(filename, "hostveil-report-"), map[bool]string{true: "json", false: "csv"}[m.exportIdx == 0])
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

func (m model) View() tea.View {
	t := m.theme()

	var content string
	if m.phase == "loading" {
		content = m.renderLoading()
	} else {
		content = m.renderMain()
	}

	if m.modal != modalNone && m.phase != "loading" {
		content = m.renderWithModal(content)
	}

	v := tea.NewView(content)
	v.AltScreen = true
	v.BackgroundColor = lipgloss.Color(t.Background)
	v.ForegroundColor = lipgloss.Color(t.Text)
	v.WindowTitle = "hostveil"
	return v
}

func (m model) theme() Theme {
	return DefaultTheme()
}

// ── filtering & sorting ──

func (m model) visibleFindings() []domain.Finding {
	items := m.snap.Findings
	f := m.filter
	filtered := make([]domain.Finding, 0, len(items))
	for _, item := range items {
		if f.severity != "all" && item.Severity.String() != f.severity {
			continue
		}
		if f.source != "all" && item.Source.String() != f.source {
			continue
		}
		if f.remediation != "all" && item.Remediation.String() != f.remediation {
			continue
		}
		if f.service != "all" && item.Service != f.service {
			continue
		}
		if f.query != "" && !findingMatches(item, f.query) {
			continue
		}
		filtered = append(filtered, item)
	}
	sortFindings(filtered, f.sortBy)
	return filtered
}

func findingMatches(f domain.Finding, q string) bool {
	q = strings.ToLower(q)
	for _, s := range []string{f.ID, f.Title, f.Description, f.HowToFix, f.Service, f.Severity.String(), f.Source.String(), f.Remediation.String()} {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

func sortFindings(findings []domain.Finding, sortBy string) {
	sevOrder := func(s domain.Severity) int {
		switch s {
		case domain.SeverityCritical:
			return 0
		case domain.SeverityHigh:
			return 1
		case domain.SeverityMedium:
			return 2
		default:
			return 3
		}
	}
	switch sortBy {
	case "severity":
		sort.Slice(findings, func(i, j int) bool {
			si, sj := sevOrder(findings[i].Severity), sevOrder(findings[j].Severity)
			if si != sj {
				return si < sj
			}
			return findings[i].Title < findings[j].Title
		})
	case "source":
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Source != findings[j].Source {
				return findings[i].Source.String() < findings[j].Source.String()
			}
			return sevOrder(findings[i].Severity) < sevOrder(findings[j].Severity)
		})
	case "title":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Title < findings[j].Title
		})
	case "remediation":
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Remediation != findings[j].Remediation {
				return findings[i].Remediation.String() < findings[j].Remediation.String()
			}
			return sevOrder(findings[i].Severity) < sevOrder(findings[j].Severity)
		})
	}
}

func (m *model) cycleSourceFilter() {
	switch m.filter.source {
	case "all":
		m.filter.source = "trivy"
	case "trivy":
		m.filter.source = "lynis"
	default:
		m.filter.source = "all"
	}
}

func (m *model) cycleRemediationFilter() {
	switch m.filter.remediation {
	case "all":
		m.filter.remediation = "auto"
	case "auto":
		m.filter.remediation = "review"
	case "review":
		m.filter.remediation = "unavailable"
	case "unavailable":
		m.filter.remediation = "manual"
	default:
		m.filter.remediation = "all"
	}
}

func (m *model) cycleServiceFilter() {
	services := []string{"all"}
	seen := map[string]bool{"all": true}
	for _, f := range m.snap.Findings {
		if f.Service != "" && !seen[f.Service] {
			seen[f.Service] = true
			services = append(services, f.Service)
		}
	}
	if len(services) <= 1 {
		return
	}
	idx := -1
	for i, s := range services {
		if s == m.filter.service {
			idx = i
			break
		}
	}
	next := (idx + 1) % len(services)
	m.filter.service = services[next]
}

func (m *model) cycleSortOrder() {
	switch m.filter.sortBy {
	case "severity":
		m.filter.sortBy = "source"
	case "source":
		m.filter.sortBy = "title"
	case "title":
		m.filter.sortBy = "remediation"
	default:
		m.filter.sortBy = "severity"
	}
}

// ── table management ──

func (m *model) rebuildTable() {
	m.live.Recalculate()
	m.snap = m.live.Snapshot()
	m.snapOK = true
	visible := m.visibleFindings()
	rows := make([]table.Row, len(visible))
	layout := m.tableLayout()
	cursor := m.table.Cursor()
	for i, f := range visible {
		checkbox := "◇"
		if f.Remediation == domain.RemediationUnavailable {
			checkbox = "─"
		} else if m.selectedSet[f.ID] {
			checkbox = "◆"
		}
		sevText := strings.ToUpper(f.Severity.String())
		src := f.Source.String()
		id := shortID(f.ID)
		title := findingTitle(f)
		fixLabel := remediationShortLabel(f.Remediation)
		if f.Fixed {
			sevText = "✓"
			src = ""
			title = "✓ " + title
			fixLabel = "Fixed"
		}
		switch layout {
		case "compact":
			rows[i] = table.Row{checkbox, sevText, fit(title, m.findingColumnWidth(layout))}
		case "medium":
			rows[i] = table.Row{checkbox, sevText, id, fit(title, m.findingColumnWidth(layout)), fixLabel}
		default:
			rows[i] = table.Row{checkbox, sevText, src, id, fit(title, m.findingColumnWidth(layout)), fixLabel}
		}
	}
	m.table.SetRows(nil)
	m.updateTableColumns()
	m.table.SetRows(rows)
	m.table.SetCursor(cursor)
	m.table.SetWidth(m.listTableWidth())
	m.table.SetHeight(m.listHeight())
	if m.width > 0 && m.height > 0 {
		m.updateDetailViewport()
	}
}

func (m *model) updateDetailViewport() {
	contentWidth := m.detailContentWidth()
	if m.phase == "loading" {
		m.viewport.SetContent("Scanning in progress...\n\nResults will appear when scans complete.")
		m.viewport.SetWidth(contentWidth)
		m.viewport.SetHeight(m.detailHeight())
		m.viewport.GotoTop()
		return
	}
	visible := m.visibleFindings()
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(visible) {
		m.viewport.SetContent("")
		return
	}
	t := m.theme()
	m.viewport.SetContent(renderDetailContent(t, &visible[idx], contentWidth))
	m.viewport.SetWidth(contentWidth)
	m.viewport.SetHeight(m.detailHeight())
	m.viewport.GotoTop()
}

// ── layout ──

func (m model) tableLayout() string {
	w := m.listWidth()
	if w < 64 {
		return "compact"
	}
	if w < 88 {
		return "medium"
	}
	return "full"
}

func (m *model) updateTableColumns() {
	switch m.tableLayout() {
	case "compact":
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Finding", Width: m.findingColumnWidth("compact")},
		})
	case "medium":
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: m.findingColumnWidth("medium")},
			{Title: "Fix", Width: 11},
		})
	default:
		m.table.SetColumns([]table.Column{
			{Title: " ", Width: 3},
			{Title: "Severity", Width: 8},
			{Title: "Source", Width: 6},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: m.findingColumnWidth("full")},
			{Title: "Fix", Width: 11},
		})
	}
}

func (m model) findingColumnWidth(layout string) int {
	w := m.listTableWidth()
	switch layout {
	case "compact":
		return max(12, w-3-8-6)
	case "medium":
		return max(14, w-3-8-14-11-18)
	default:
		return max(16, w-3-8-6-14-11-24)
	}
}

func (m model) listWidth() int {
	fw := m.filterWidth()
	if fw > 0 {
		return max(52, m.width-fw-m.detailWidth()-4)
	}
	if m.splitDetail() {
		return max(52, m.width-m.detailWidth()-2)
	}
	return max(1, m.width-4)
}

func (m model) listTableWidth() int {
	return max(20, m.listWidth()-4)
}

func (m model) listHeight() int {
	h := m.bodyHeight() - 12
	if h < 4 {
		return 4
	}
	return h
}

func (m model) detailWidth() int {
	if m.filterWidth() > 0 {
		remaining := m.width - m.filterWidth() - 4
		d := remaining * 2 / 5
		if d < 44 {
			return 44
		}
		if d > 66 {
			return 66
		}
		return d
	}
	if m.splitDetail() {
		d := m.width * 2 / 5
		if d < 42 {
			return 42
		}
		if d > 58 {
			return 58
		}
		return d
	}
	return max(1, m.width-4)
}

func (m model) detailHeight() int {
	h := m.bodyHeight() - 6
	if h < 4 {
		return 4
	}
	return h
}

func (m model) bodyHeight() int {
	if m.height <= 0 || m.width <= 0 {
		return 10
	}
	h := m.height - m.headerH - m.metricsH
	if h < 4 {
		return 4
	}
	return h
}

func (m model) splitDetail() bool {
	return m.width >= 116
}

func (m model) inlineDetail() bool {
	return m.filterWidth() > 0 || m.splitDetail()
}

func (m model) detailContentWidth() int {
	return max(20, m.detailWidth()-8)
}

func (m model) panelAt(x int) paneMode {
	fw := m.filterWidth()
	if fw > 0 {
		listStart := fw + 2
		listEnd := listStart + m.listWidth() + 2
		if x >= listEnd {
			return paneDetail
		}
		return paneList
	}
	if m.splitDetail() {
		listEnd := m.listWidth() + 2
		if x >= listEnd {
			return paneDetail
		}
		return paneList
	}
	return m.mode
}

func (m model) startRescan() model {
	m.live.ResetForRescan()
	m.phase = "loading"
	m.toast = "Rescanning..."
	m.toastUntil = time.Time{}
	go func() {
		scan.RunSingleTool(m.live, m.fixReg, "trivy")
		scan.RunSingleTool(m.live, m.fixReg, "lynis")
		m.live.Finalize()
		if m.send != nil {
			m.send(tickMsg{})
		}
	}()
	return m
}

// ── keymap for help ──

type keyMap struct {
	bindings []key.Binding
}

func (k keyMap) ShortHelp() []key.Binding  { return k.bindings }
func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.bindings} }

func (m model) listKeyMap() keyMap {
	binds := []key.Binding{
		key.NewBinding(key.WithKeys("↑/↓"), key.WithHelp("j/k", "navigate")),
		key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "detail")),
		key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
		key.NewBinding(key.WithKeys("space"), key.WithHelp("space", "select")),
		key.NewBinding(key.WithKeys("0-4"), key.WithHelp("0-4", "severity filter")),
		key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "source: "+m.filter.source)),
		key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "remediation: "+m.filter.remediation)),
		key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "sort: "+m.filter.sortBy)),
		key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "clear filters")),
		key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
		key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
		key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl+r", "recalc score")),
		key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "rescan")),
		key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export")),
		key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
	}
	return keyMap{binds}
}

func (m model) detailKeyMap() keyMap {
	return keyMap{[]key.Binding{
		key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		key.NewBinding(key.WithKeys("↑/↓"), key.WithHelp("j/k", "scroll")),
		key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
		key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
		key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
		key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl+r", "recalc score")),
		key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "rescan")),
		key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export")),
		key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	}}
}

func tickCmd() tea.Cmd {
	return tea.Tick(domain.TUITickInterval, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}
