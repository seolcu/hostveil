// Package tui provides the Bubble Tea terminal user interface.
package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
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
	modalDryRun
	modalFixConfirm
	modalFixResult
	modalFixProgress
	modalExport
)

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
	fixTarget      *fix.Fix
	fixActionIdx   int
	fixResult      string
	dryRunActions  []dryRunAction
	dryRunApplyIdx int

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
			sortDir:     "asc",
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
				svc := visible[idx].Service
				for i := range m.snap.Findings {
					if m.snap.Findings[i].ID == id && (svc == "" || m.snap.Findings[i].Service == svc) {
						m.snap.Findings[i].Fixed = true
					}
				}
				m.live.MarkFixed(id, svc)
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
			switch target {
			case paneList:
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
			case paneDetail:
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
	case "O":
		if m.filter.sortDir == "asc" {
			m.filter.sortDir = "desc"
		} else {
			m.filter.sortDir = "asc"
		}
		m.rebuildTable()
		m.toast = "Sort: " + m.filter.sortBy + " (" + m.filter.sortDir + ")"
		m.toastUntil = time.Now().Add(3 * time.Second)
		return m, nil
	case "ctrl+a":
		visible := m.visibleFindings()
		if len(m.selectedSet) == len(visible) {
			m.selectedSet = make(map[string]bool)
		} else {
			m.selectedSet = make(map[string]bool)
			for _, f := range visible {
				if f.Remediation != domain.RemediationUnavailable {
					m.selectedSet[f.ID] = true
				}
			}
		}
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
	case modalDryRun:
		switch msg.String() {
		case "up", "k":
			if m.dryRunApplyIdx > 0 {
				m.dryRunApplyIdx--
			}
		case "down", "j":
			if m.dryRunApplyIdx < len(m.dryRunActions)-1 {
				m.dryRunApplyIdx++
			}
		case "enter", "l":
			m.fixActionIdx = m.dryRunApplyIdx
			if m.fixTarget != nil && m.fixActionIdx < len(m.fixTarget.Actions) {
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
			m.dryRunActions = nil
			m.modal = modalNone
		}
	case modalFixConfirm:
		switch msg.String() {
		case "y", "Y":
			m.modal = modalNone
			m.dryRunActions = nil
			m2, cmd := m.applyFix()
			return m2, cmd
		case "n", "N", "q", "esc":
			m.fixTarget = nil
			m.dryRunActions = nil
			m.modal = modalNone
		}
	case modalFixResult:
		switch msg.String() {
		case "q", "esc", "enter":
			m.fixTarget = nil
			m.dryRunActions = nil
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

func tickCmd() tea.Cmd {
	return tea.Tick(domain.TUITickInterval, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}
