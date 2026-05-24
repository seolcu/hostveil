package tui

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

var Version = "v2.0.0-dev"

var defaultKeyList = []key.Binding{
	key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	key.NewBinding(key.WithKeys("enter", "l", "right"), key.WithHelp("enter", "open")),
	key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
	key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "theme")),
	key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}

type model struct {
	result     *domain.ScanResult
	themeIdx   int
	selected   int
	showDetail bool
	showHelp   bool
	showTheme  bool
	themeCur   int
	help       help.Model
	detailVP   viewport.Model
	width      int
	height     int
}

func NewApp(result *domain.ScanResult) *model {
	return &model{
		result:   result,
		help:     help.New(),
		detailVP: viewport.New(60, 20),
	}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		s := msg.String()

		if s == "ctrl+c" {
			return m, tea.Quit
		}

		if m.showTheme {
			switch s {
			case "esc":
				m.showTheme = false
				m.themeCur = 0
			case "up", "k":
				if m.themeCur > 0 {
					m.themeCur--
				}
			case "down", "j":
				if m.themeCur < len(AllThemes())-1 {
					m.themeCur++
				}
			case "enter", "l", "right":
				m.themeIdx = m.themeCur
				m.showTheme = false
				m.themeCur = 0
			}
			return m, nil
		}

		switch s {
		case "?":
			m.showHelp = !m.showHelp
		case "s":
			m.showTheme = true
			m.showDetail = false
		case "esc":
			if m.showHelp {
				m.showHelp = false
			} else if m.showDetail {
				m.showDetail = false
			}
		case "q":
			return m, tea.Quit
		case "up", "k":
			if m.showDetail {
				m.detailVP.LineUp(1)
			} else if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.showDetail {
				m.detailVP.LineDown(1)
			} else if m.selected < len(m.result.Findings)-1 {
				m.selected++
			}
		case "enter", "l", "right":
			if !m.showDetail && m.selected < len(m.result.Findings) {
				m.showDetail = true
				m.showHelp = false
				content := renderDetail(AllThemes()[m.themeIdx], &m.result.Findings[m.selected], m.width/2, 20)
				m.detailVP.SetContent(content)
				m.detailVP.GotoTop()
			}
		}
	}
	return m, nil
}

func (m model) View() string {
	t := AllThemes()[m.themeIdx]

	if m.showTheme {
		return renderSettings(t, AllThemes(), m.themeCur, m.width, m.height)
	}

	header := renderHeader(t, m.width)
	overview := renderOverview(t, m.result, m.width)

	var footer string
	if m.showHelp {
		footer = m.help.FullHelpView([][]key.Binding{defaultKeyList})
	} else {
		footer = m.help.ShortHelpView(defaultKeyList)
	}
	footer = lipgloss.NewStyle().
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Width(m.width).
		Render(footer)

	bodyTop := lineCount(header) + lineCount(overview)
	footerH := lineCount(footer)
	bodyHeight := m.height - bodyTop - footerH
	if bodyHeight < 3 {
		bodyHeight = 3
	}

	listWidth := m.width
	if m.showDetail && m.width >= 60 {
		listWidth = m.width / 2
	}

	list := renderFindingsList(t, m.result.Findings, m.selected, listWidth, bodyHeight)

	if m.showDetail && m.selected < len(m.result.Findings) {
		detailWidth := m.width - listWidth - 2
		detail := renderDetail(t, &m.result.Findings[m.selected], detailWidth, bodyHeight)
		body := lipgloss.JoinHorizontal(lipgloss.Top,
			list,
			lipgloss.NewStyle().Width(1).Render(" "),
			detail,
		)
		return lipgloss.JoinVertical(lipgloss.Top, header, overview, body, footer)
	}

	return lipgloss.JoinVertical(lipgloss.Top, header, overview, list, footer)
}
