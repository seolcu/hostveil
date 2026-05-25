// Package tui provides the Bubble Tea terminal user interface.
package tui

import (
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
)

var Version = "v2.0.0-dev"

type paneMode int

const (
	paneList paneMode = iota
	paneDetail
)

type modalMode int

const (
	modalNone modalMode = iota
	modalHelp
	modalTheme
	modalFilter
	modalFixConfirm
	modalFixResult
)

type filterState struct {
	query       string
	severity    string
	source      string
	remediation string
	sortBy      string
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
	mode     paneMode
	filter   filterState
	themeIdx int

	// modals
	modal       modalMode
	themeCursor int
	themeSaved  int

	// fix
	fixTarget    *fix.Fix
	fixActionIdx int
	fixResult    string

	// toast
	toast      string
	toastClear int
}

type tickMsg struct{}
type fixResultMsg struct{ result fix.FixResult }

func NewApp(live *domain.ScanProgress, noUpdateCheck bool, reg *fix.Registry) *model {
	s := spinner.New(spinner.WithSpinner(spinner.Dot))

	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "Sev", Width: 5},
			{Title: "Src", Width: 4},
			{Title: "ID", Width: 14},
			{Title: "Finding", Width: 0},
			{Title: "Fix", Width: 12},
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
		live:    live,
		fixReg:  reg,
		spinner: s,
		table:     t,
		viewport:  vp,
		help:      help.New(),
		searchBox: search,
		filter: filterState{
			severity:    "all",
			source:      "all",
			remediation: "all",
			sortBy:      "severity",
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
		m.table.SetWidth(m.listWidth())
		m.viewport.SetWidth(m.detailWidth())
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
				if m.width > 0 && m.height > 0 {
					m.rebuildTable()
				}
			}
			return m, tickCmd()
		}
		if m.toast != "" && m.toastClear > 0 {
			m.toastClear--
			if m.toastClear == 0 {
				m.toast = ""
			}
			return m, tickCmd()
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		if m.phase == "loading" {
			return m, tea.Batch(cmd, func() tea.Msg { return m.spinner.Tick() })
		}
		return m, cmd

	case fixResultMsg:
		if msg.result.Success {
			m.fixResult = "✓ " + msg.result.Label
		} else {
			m.fixResult = "✗ " + msg.result.Error
		}
		m.modal = modalFixResult
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
	}
	return m, nil
}

func (m model) updateMain(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()

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
	case "t":
		m.openThemeModal()
		return m, nil
	case "/":
		m.modal = modalFilter
		m.searchBox.SetValue(m.filter.query)
		m.searchBox.Focus()
		return m, nil
	case "f":
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
	case "R":
		m.filter.query = ""
		m.filter.severity = "all"
		m.filter.source = "all"
		m.filter.remediation = "all"
		m.rebuildTable()
		m.toast = "Filters cleared"
		m.toastClear = 3
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
	}

	// Detail mode: delegate to viewport for scrolling
	if m.mode == paneDetail {
		switch keyStr {
		case "esc", "h", "left":
			m.mode = paneList
			m.updateDetailViewport()
			return m, nil
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}

	// List mode: delegate to table for navigation
	switch keyStr {
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
	case modalTheme:
		switch msg.String() {
		case "q", "esc":
			m.themeIdx = m.themeSaved
			m.themeCursor = m.themeSaved
			m.modal = modalNone
		case "up", "k":
			if m.themeCursor > 0 {
				m.themeCursor--
				m.themeIdx = m.themeCursor
			}
		case "down", "j":
			if m.themeCursor < len(AllThemes())-1 {
				m.themeCursor++
				m.themeIdx = m.themeCursor
			}
		case "enter", "l", "right":
			m.themeIdx = m.themeCursor
			m.themeSaved = m.themeIdx
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
	}
	return m, nil
}

func (m model) runFix() (tea.Model, tea.Cmd) {
	if m.fixReg == nil {
		m.toast = "Fix engine not available"
		m.toastClear = 5
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
		m.toastClear = 5
		return m, nil
	}
	m.fixTarget = f
	m.fixActionIdx = 0

	switch f.Class() {
	case domain.RemediationAuto:
		if f.Actions[0].Warning != "" {
			m.modal = modalFixConfirm
			return m, nil
		}
		m.toast = "Applying fix..."
		m.toastClear = 5
		return m.applyFix()
	case domain.RemediationReview:
		m.toast = "Applying fix..."
		m.toastClear = 5
		m.modal = modalFixConfirm
		return m, nil
	case domain.RemediationManual:
		m.fixResult = "ℹ " + f.Actions[0].Description
		m.modal = modalFixResult
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

func (m *model) openThemeModal() {
	m.themeSaved = m.themeIdx
	m.themeCursor = m.themeIdx
	m.modal = modalTheme
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
	themes := AllThemes()
	if m.themeIdx < 0 || m.themeIdx >= len(themes) {
		return DefaultTheme()
	}
	return themes[m.themeIdx]
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
		m.filter.remediation = "manual"
	default:
		m.filter.remediation = "all"
	}
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
	visible := m.visibleFindings()
	rows := make([]table.Row, len(visible))
	for i, f := range visible {
		id := shortID(f.ID)
		rows[i] = table.Row{
			strings.ToUpper(short(f.Severity.String(), 3)),
			strings.ToUpper(short(f.Source.String(), 3)),
			id,
			f.Title,
			f.Remediation.Label(),
		}
	}
	m.table.SetRows(rows)
	m.table.SetWidth(m.listWidth())
	m.table.SetHeight(m.listHeight())
}

func (m *model) updateDetailViewport() {
	visible := m.visibleFindings()
	idx := m.table.Cursor()
	if idx < 0 || idx >= len(visible) {
		m.viewport.SetContent("")
		return
	}
	t := m.theme()
	m.viewport.SetContent(renderDetailContent(t, &visible[idx], m.detailWidth()-4))
	m.viewport.SetWidth(m.detailWidth())
	m.viewport.SetHeight(m.detailHeight())
	m.viewport.GotoTop()
}

// ── layout ──

func (m model) listWidth() int {
	if m.width >= 180 {
		return m.width * 3 / 5
	}
	if m.width >= 130 {
		return m.width / 2
	}
	return m.width - 4
}

func (m model) listHeight() int {
	h := m.height - 10
	if h < 4 {
		return 4
	}
	return h
}

func (m model) detailWidth() int {
	if m.width >= 130 {
		return m.width - m.listWidth() - 4
	}
	return m.width - 4
}

func (m model) detailHeight() int {
	return m.listHeight()
}

// ── keymap for help ──

type keyMap struct {
	bindings []key.Binding
}

func (k keyMap) ShortHelp() []key.Binding { return k.bindings }
func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.bindings} }

func (m model) listKeyMap() keyMap {
	binds := []key.Binding{
		key.NewBinding(key.WithKeys("↑/↓"), key.WithHelp("j/k", "navigate")),
		key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "detail")),
		key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
		key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "theme")),
		key.NewBinding(key.WithKeys("0-4"), key.WithHelp("0-4", "severity filter")),
		key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "source: "+m.filter.source)),
		key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "sort: "+m.filter.sortBy)),
		key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "clear filters")),
		key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
		key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
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
		key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	}}
}

func tickCmd() tea.Cmd {
	return tea.Tick(domain.TUITickInterval, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}
