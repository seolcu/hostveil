package tui

import (
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

var Version = "v2.0.0-dev"

type screenMode int

const (
	modeList screenMode = iota
	modeDetail
)

type modalMode int

const (
	modalNone modalMode = iota
	modalHelp
	modalTheme
	modalFixConfirm
	modalFixResult
)

type model struct {
	live   *domain.ScanProgress
	snap   domain.Snapshot
	fixReg *fix.Registry
	send   func(tea.Msg)
	noSync bool

	width  int
	height int

	mode  screenMode
	modal modalMode

	selected     int
	listOffset   int
	detailOffset int

	themeIdx    int
	themeCursor int
	themeSaved  int

	fixTarget   *fix.Fix
	fixActionIdx int
	fixResult   string

	help      help.Model
	tickCount int
}

type tickMsg struct{}
type fixResultMsg struct{ result fix.FixResult }

func NewApp(live *domain.ScanProgress, noUpdateCheck bool, reg *fix.Registry) *model {
	return &model{
		live:   live,
		fixReg: reg,
		noSync: noUpdateCheck,
		help:   help.New(),
	}
}

func (m *model) SetProgram(send func(tea.Msg)) {
	m.send = send
}

func (m model) Init() tea.Cmd {
	return tickCmd()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m.snap = m.live.Snapshot()

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.clampSelection()
		m.keepSelectionVisible()
		m.clampDetailOffset()

	case domain.ProgressTick, tickMsg:
		m.tickCount++
		if m.snap.Phase == "loading" {
			return m, tickCmd()
		}
		return m, nil

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
		if m.snap.Phase == "loading" {
			if msg.String() == "q" {
				return m, tea.Quit
			}
			return m, nil
		}
		if m.modal != modalNone {
			return m.updateModal(msg)
		}
		switch m.mode {
		case modeDetail:
			return m.updateDetail(msg)
		default:
			return m.updateList(msg)
		}
	}
	return m, nil
}

func (m model) updateList(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "?":
		m.modal = modalHelp
	case "s":
		m.openThemeModal()
	case "f":
		return m.runFix()
	case "up", "k":
		if m.selected > 0 {
			m.selected--
			m.keepSelectionVisible()
		}
	case "down", "j":
		if m.selected < len(m.snap.Findings)-1 {
			m.selected++
			m.keepSelectionVisible()
		}
	case "enter", "l", "right":
		if len(m.snap.Findings) > 0 {
			m.mode = modeDetail
			m.detailOffset = 0
		}
	}
	return m, nil
}

func (m model) updateDetail(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		m.mode = modeList
		m.detailOffset = 0
	case "?":
		m.modal = modalHelp
	case "s":
		m.openThemeModal()
	case "f":
		return m.runFix()
	case "up", "k":
		if m.detailOffset > 0 {
			m.detailOffset--
		}
	case "down", "j":
		if m.detailOffset < m.detailScrollLimit() {
			m.detailOffset++
		}
	}
	return m, nil
}

func (m model) updateModal(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.modal {
	case modalHelp:
		switch msg.String() {
		case "q", "esc", "?", "enter", "l", "right":
			m.modal = modalNone
		}
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
		case "q", "esc", "enter", "l", "right":
			m.fixTarget = nil
			m.modal = modalNone
		}
	}
	return m, nil
}

func (m model) runFix() (tea.Model, tea.Cmd) {
	if m.fixReg == nil || m.selected >= len(m.snap.Findings) {
		return m, nil
	}
	f := m.fixReg.Lookup(m.snap.Findings[m.selected].ID)
	if f == nil {
		return m, nil
	}
	m.fixTarget = f
	m.fixActionIdx = 0

	switch f.Class() {
	case domain.RemediationAuto:
		if f.Warning != "" {
			m.modal = modalFixConfirm
			return m, nil
		}
		return m.applyFix()
	case domain.RemediationReview:
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

	finding := m.snap.Findings[m.selected]
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
	if m.snap.Phase == "loading" {
		content = renderLoading(m)
	} else {
		content = renderBase(m)
	}

	if m.modal != modalNone && m.snap.Phase != "loading" {
		content = renderWithModal(m, content)
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

func (m *model) clampSelection() {
	if len(m.snap.Findings) == 0 {
		m.selected = 0
		m.listOffset = 0
		return
	}
	if m.selected < 0 {
		m.selected = 0
	}
	if m.selected >= len(m.snap.Findings) {
		m.selected = len(m.snap.Findings) - 1
	}
}

func (m *model) keepSelectionVisible() {
	l := computeLayout(m.width, m.height, m.mode == modeDetail)
	visible := l.listH
	if visible < 1 {
		visible = 1
	}
	if m.selected < m.listOffset {
		m.listOffset = m.selected
	}
	if m.selected >= m.listOffset+visible {
		m.listOffset = m.selected - visible + 1
	}
	if m.listOffset < 0 {
		m.listOffset = 0
	}
}

func (m *model) clampDetailOffset() {
	limit := m.detailScrollLimit()
	if m.detailOffset > limit {
		m.detailOffset = limit
	}
	if m.detailOffset < 0 {
		m.detailOffset = 0
	}
}

func (m model) detailScrollLimit() int {
	if len(m.snap.Findings) == 0 || m.selected >= len(m.snap.Findings) {
		return 0
	}
	l := computeLayout(m.width, m.height, m.mode == modeDetail)
	content := renderDetailContent(m.theme(), &m.snap.Findings[m.selected], max(0, l.detailW-4))
	limit := lipgloss.Height(content) - max(1, l.bodyH-2)
	if limit < 0 {
		return 0
	}
	return limit
}

type keyMap struct {
	bindings []key.Binding
}

func (k keyMap) ShortHelp() []key.Binding { return k.bindings }

func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.bindings} }

func keyBindings(m model) keyMap {
	if m.modal != modalNone {
		switch m.modal {
		case modalTheme:
			return keyMap{[]key.Binding{
				key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "preview up")),
				key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "preview down")),
				key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
				key.NewBinding(key.WithKeys("esc", "q"), key.WithHelp("esc/q", "cancel")),
			}}
		case modalFixConfirm:
			return keyMap{[]key.Binding{
				key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "apply")),
				key.NewBinding(key.WithKeys("n", "esc"), key.WithHelp("n/esc", "cancel")),
			}}
		case modalFixResult:
			return keyMap{[]key.Binding{
				key.NewBinding(key.WithKeys("enter", "q"), key.WithHelp("enter/q", "close")),
			}}
		}
		return keyMap{[]key.Binding{
			key.NewBinding(key.WithKeys("esc", "q", "?"), key.WithHelp("esc/q/?", "close")),
		}}
	}

	if m.mode == modeDetail {
		return keyMap{[]key.Binding{
			key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "scroll up")),
			key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "scroll down")),
			key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
			key.NewBinding(key.WithKeys("esc", "q"), key.WithHelp("esc/q", "back")),
			key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
			key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "theme")),
		}}
	}

	return keyMap{[]key.Binding{
		key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		key.NewBinding(key.WithKeys("enter", "l", "right"), key.WithHelp("enter", "details")),
		key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
		key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "theme")),
		key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
	}}
}

func tickCmd() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}
