package tui

import (
	"fmt"
	"strings"

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
	keys          keyMap

	theme    Theme
	overview *overviewModel
	findings *findingsModel
	history  *historyModel
	settings *settingsModel
	help     *helpModel
}

type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Left   key.Binding
	Right  key.Binding
	Enter  key.Binding
	Tab    key.Binding
	Quit   key.Binding
	Filter key.Binding
}

func defaultKeyMap() keyMap {
	return keyMap{
		Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Left:   key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("←/h", "back")),
		Right:  key.NewBinding(key.WithKeys("right", "l", "enter"), key.WithHelp("→/l", "select")),
		Enter:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
		Tab:    key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next panel")),
		Quit:   key.NewBinding(key.WithKeys("q", "esc"), key.WithHelp("q/esc", "quit")),
		Filter: key.NewBinding(key.WithKeys("s", "x", "z", "m", "v", "o"), key.WithHelp("s/x/z/m/v/o", "filter")),
	}
}

func NewApp(result *domain.ScanResult) *appModel {
	return &appModel{
		currentScreen: screenOverview,
		scanResult:    result,
		keys:          defaultKeyMap(),
		theme:         DefaultTheme(),
		overview:      &overviewModel{},
		findings:      newFindingsModel(result.Findings),
		history:       &historyModel{},
		settings:      newSettingsModel(),
		help:          &helpModel{},
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

	case tea.KeyMsg:
		s := msg.String()

		// Global overlays take priority
		if m.help.show {
			if s == "?" || s == "esc" || s == "q" {
				m.help.Toggle()
			}
			return m, nil
		}
		if m.settings.IsOpen() {
			if s == "S" || s == "esc" || s == "q" {
				m.settings.Toggle()
			} else {
				oldTheme := m.settings.themeName
				m.settings.Update(s)
				if m.settings.themeName != oldTheme {
					m.theme = GetTheme(m.settings.themeName)
				}
			}
			return m, nil
		}

		switch {
		case key.Matches(msg, m.keys.Quit) && !m.settings.IsOpen():
			return m, tea.Quit
		case s == "?":
			m.help.Toggle()
		case s == "1":
			m.currentScreen = screenOverview
		case s == "2":
			m.currentScreen = screenFindings
		case s == "3":
			m.currentScreen = screenHistory
		case s == "S":
			m.settings.Toggle()
		case s == "h" && m.currentScreen == screenOverview:
			// Host triage: switch to findings filtered to host scope
			m.currentScreen = screenFindings
			m.findings.hostTriageMode = true
			m.findings.scopeFilter = "host"
			m.findings.applyFilters()
		case s == "f" && m.currentScreen == screenFindings && m.findings.selected < len(m.findings.list):
			f := m.findings.list[m.findings.selected]
			if f.IsFixable() {
				m.currentScreen = screenFindings
			}
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

	// Pad body so footer stays at terminal bottom
	totalLines := strings.Count(header, "\n") + 1 + strings.Count(body, "\n") + 1 + strings.Count(footer, "\n") + 1
	availableLines := m.height
	if totalLines < availableLines {
		body += strings.Repeat("\n", availableLines-totalLines)
	}

	view := lipgloss.JoinVertical(lipgloss.Top, header, body, footer)

	// Overlays
	if m.help.show {
		overlay := m.help.Render(m.theme, m.width, m.height)
		view = lipgloss.Place(m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			overlay,
			lipgloss.WithWhitespaceChars(" "),
		)
	} else if m.settings.IsOpen() {
		overlay := m.settings.Render(m.theme, m.width, m.height)
		view = lipgloss.Place(m.width, m.height,
			lipgloss.Center, lipgloss.Center,
			overlay,
			lipgloss.WithWhitespaceChars(" "),
		)
	}

	return view
}

func (m *appModel) renderHeader() string {
	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.theme.Text)).
		Bold(true).
		Render("hostveil")

	score := lipgloss.NewStyle().
		Foreground(lipgloss.Color(m.theme.Accent)).
		Render(fmtScore(m.scanResult))

	headerStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(m.theme.Surface)).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(m.theme.Border)).
		Padding(0, 2).
		Width(m.width)

	return headerStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, title, "   ", score))
}

func (m *appModel) renderFooter() string {
	nav := " [1] Overview  [2] Findings  [3] History "
	hint := " [?] Help  [q] Quit "

	style := lipgloss.NewStyle().
		Background(lipgloss.Color(m.theme.Surface)).
		BorderTop(true).
		BorderForeground(lipgloss.Color(m.theme.Border)).
		Padding(0, 2).
		Width(m.width)

	return style.Render(lipgloss.JoinHorizontal(lipgloss.Center, nav, hint))
}

func (m *appModel) renderOverview() string {
	return m.overview.render(m.scanResult, m.theme, m.width, m.height-4)
}

func (m *appModel) renderFindings() string {
	return m.findings.render(m.theme, m.width, m.height-4)
}

func (m *appModel) renderHistory() string {
	return m.history.render(m.scanResult, m.theme, m.width, m.height-4)
}

func fmtScore(r *domain.ScanResult) string {
	return fmt.Sprintf("Score: %d (%s)  |  %d findings", r.ScoreReport.Overall, r.ScoreReport.Grade(), r.TotalFindings())
}
