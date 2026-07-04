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

var Version = "v2.6.0"

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
	modalTheme
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

	// theme
	themeName string
	themeIdx  int

	// cached render heights
	headerH  int
	metricsH int

	// per-render-frame cache for visibleFindings
	visibleCache []domain.Finding
}

type tickMsg struct{}

func NewApp(live *domain.ScanProgress, reg *fix.Registry) *model {
	cfg := LoadConfig()
	themeName := cfg.Theme
	themeIdx := 0
	for i, id := range ThemeIDs() {
		if id == themeName {
			themeIdx = i
			break
		}
	}

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
		table.WithStyles(tableStyles(LookupTheme(themeName))),
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
		phase:     "loading",
		themeName: themeName,
		themeIdx:  themeIdx,
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
				m.live.MarkFixed(id, svc)
				// Cascade to related findings, matching the Web UI's
				// handleFix behavior: only for exact-ID registrations
				// (never wildcards, e.g. trivy.cve-*), so a generic
				// fix never silently marks other findings resolved.
				if svc != "" && m.fixReg != nil && m.fixReg.HasExactEntry(id) {
					f := m.fixTarget
					m.live.MarkRelatedFixed(id, svc, func(candidateID string) bool {
						return m.fixReg.Lookup(candidateID) == f
					})
				}
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
		headerH := m.headerH
		metricsH := m.metricsH
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

func (m model) View() tea.View {
	t := m.theme()

	// Invalidate per-frame caches at the start of each render frame.
	m.invalidateVisibleCache()

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
	return LookupTheme(m.themeName)
}

func (m model) applyTheme(name string) model {
	m.themeName = NormalizeThemeID(name)
	for i, id := range ThemeIDs() {
		if id == m.themeName {
			m.themeIdx = i
			break
		}
	}
	m.table.SetStyles(tableStyles(m.theme()))
	_ = SaveConfig(Config{Theme: m.themeName})
	return m
}

func (m model) startRescan() model {
	m.live.ResetForRescan()
	m.phase = "loading"
	m.toast = "Rescanning..."
	m.toastUntil = time.Time{}
	go func() {
		scan.RunSingleTool(m.live, m.fixReg, "compose")
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
