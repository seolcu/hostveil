package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type screen int

const (
	screenOverview screen = iota
	screenFindings
	screenHistory
)

type appModel struct {
	currentScreen screen
	width         int
	height        int
	scanResult    *domain.ScanResult
	tick          int
	help          help.Model
	keys          keyMap
	focus         int // which panel is focused

	theme       Theme
	overview    *overviewModel
	findings    *findingsModel
}

type keyMap struct {
	Up       key.Binding
	Down     key.Binding
	Left     key.Binding
	Right    key.Binding
	Enter    key.Binding
	Tab      key.Binding
	Quit     key.Binding
	Filter   key.Binding
	Search   key.Binding
	Fix      key.Binding
	Settings key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Left:     key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "back")),
		Right:    key.NewBinding(key.WithKeys("right", "l", "enter"), key.WithHelp("→/l", "select")),
		Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		Tab:      key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next panel")),
		Quit:     key.NewBinding(key.WithKeys("q", "esc"), key.WithHelp("q/esc", "quit")),
		Filter:   key.NewBinding(key.WithKeys("s", "x", "m", "v", "o"), key.WithHelp("s/x/m/v/o", "filter")),
		Search:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		Fix:      key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "fix")),
		Settings: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "settings")),
	}
}

func NewApp(result *domain.ScanResult) *appModel {
	return &appModel{
		currentScreen: screenOverview,
		scanResult:    result,
		help:          help.New(),
		keys:          defaultKeyMap(),
		theme:         DefaultTheme(),
		overview:      &overviewModel{},
		findings:      newFindingsModel(result.Findings),
	}
}

func (m *appModel) Init() tea.Cmd {
	return nil
}

func (m *appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.Width = msg.Width

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case msg.String() == "?":
			m.help.ShowAll = !m.help.ShowAll
		case key.Matches(msg, key.NewBinding(key.WithKeys("1"))):
			m.currentScreen = screenOverview
		case key.Matches(msg, key.NewBinding(key.WithKeys("2"))):
			m.currentScreen = screenFindings
		case key.Matches(msg, key.NewBinding(key.WithKeys("3"))):
			m.currentScreen = screenHistory
		case msg.String() == "?":
			m.help.ShowAll = !m.help.ShowAll
		default:
			if m.currentScreen == screenFindings {
				m.findings.Update(msg)
			}
		}
	}

	return m, nil
}

func (m *appModel) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	header := m.renderHeader()

	var body string
	switch m.currentScreen {
	case screenOverview:
		body = m.renderOverview()
	case screenFindings:
		body = m.renderFindings()
	case screenHistory:
		body = m.renderHistory()
	}

	footer := m.renderFooter()

	return lipgloss.JoinVertical(lipgloss.Top, header, body, footer)
}

func (m *appModel) renderHeader() string {
	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.theme.Text)).
		Bold(true).
		Render("hostveil")

	score := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.theme.Accent)).
		Render(fmtScore(m.scanResult))

	header := lipgloss.NewStyle().
		BorderBottom(true).
		BorderForeground(lipgloss.Color(m.theme.Border)).
		Padding(0, 2).
		Width(m.width).
		Render(lipgloss.JoinHorizontal(lipgloss.Center, title, "   ", score))

	return header
}

func (m *appModel) renderFooter() string {
	nav := " [1] Overview  [2] Findings  [3] History "
	help := " [?] Help  [q] Quit "

	style := lipgloss.NewStyle().
		BorderTop(true).
		BorderForeground(lipgloss.Color(m.theme.Border)).
		Padding(0, 2).
		Width(m.width)

	return style.Render(lipgloss.JoinHorizontal(lipgloss.Center, nav, help))
}

func (m *appModel) renderOverview() string {
	return m.overview.render(m.scanResult, m.theme, m.width, m.height-4)
}

func (m *appModel) renderFindings() string {
	return m.findings.render(m.theme, m.width, m.height-4)
}

func (m *appModel) renderHistory() string {
	return renderHistoryPanel(m.scanResult, m.theme, m.width, m.height-4)
}

func fmtScore(r *domain.ScanResult) string {
	return fmt.Sprintf("Score: %d (%s)  |  %d findings", r.ScoreReport.Overall, r.ScoreReport.Grade(), r.TotalFindings())
}
