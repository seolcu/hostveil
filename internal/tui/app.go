package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
)

var resetSeq = regexp.MustCompile(`\x1b\[0m`)
var bgResetSeq = regexp.MustCompile(`\x1b\[49m`)

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
				if m.findings.showFixPreview {
					m.findings.showFixPreview = false
					m.findings.showDetail = true
				} else {
					if m.scanResult.Metadata.ComposeFile != "" {
						engine := fix.NewEngine(m.scanResult.Metadata.ComposeFile, m.scanResult.Findings)
						m.findings.fixPreviewContent = engine.PreviewFinding(f)
						m.findings.showFixPreview = true
					} else {
						m.findings.fixPreviewContent = "No compose file available for fix preview."
						m.findings.showFixPreview = true
					}
				}
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

	t := m.effectiveTheme()

	header := m.renderHeader(t)

	var body string
	switch m.currentScreen {
	case screenOverview:
		body = m.overview.render(m.scanResult, t, m.width, m.height-4)
	case screenFindings:
		body = m.findings.render(t, m.width, m.height-4)
	case screenHistory:
		body = m.history.render(m.scanResult, t, m.width, m.height-4)
	}

	footer := m.renderFooter(t)

	// Pad body so footer stays at terminal bottom
	totalLines := strings.Count(header, "\n") + 1 + strings.Count(body, "\n") + 1 + strings.Count(footer, "\n") + 1
	availableLines := m.height
	if totalLines < availableLines {
		body += strings.Repeat("\n", availableLines-totalLines)
	}

	content := lipgloss.JoinVertical(lipgloss.Top, header, body, footer)

	// Wrap entire render in background color, pad each line to full width
	view := applyBackground(content, t.Background, m.width, m.height)

	// Overlays — place centered on the background-filled canvas
	// We do NOT use lipgloss.Place here because its whitespace padding lacks
	// background styling, causing black bars around modals. Instead we
	// replace canvas lines manually with explicit background sequences.
	if m.help.show {
		overlay := m.help.Render(t, m.width, m.height)
		view = placeOverlayOnBackground(view, overlay, t.Background, m.width, m.height)
	} else if m.settings.IsOpen() {
		overlay := m.settings.Render(t, m.width, m.height)
		view = placeOverlayOnBackground(view, overlay, t.Background, m.width, m.height)
	}

	return view
}

func applyBackground(content string, bgColor string, width, height int) string {
	// Pad lines to fill terminal dimensions
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	for i := 0; i < height-len(lines); i++ {
		lines = append(lines, "")
	}
	for i, line := range lines {
		if len(line) < width {
			lines[i] = line + strings.Repeat(" ", width-len(line))
		}
	}
	full := strings.Join(lines, "\n")

	// Parse hex color to RGB
	r, g, b := parseHex(bgColor)
	bgSeq := fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)

	// Re-apply theme background after every reset or background-reset sequence.
	// lipgloss internally emits ESC[0m and ESC[49m between styled regions,
	// which would reveal the terminal's default background. We interpose our
	// own background color to keep the entire canvas filled.
	full = resetSeq.ReplaceAllString(full, "\x1b[0m"+bgSeq)
	full = bgResetSeq.ReplaceAllString(full, bgSeq)

	return bgSeq + full + "\x1b[49m"
}

// placeOverlayOnBackground centers overlay content on a background-filled canvas.
// Unlike lipgloss.Place, it applies background sequences to EVERY character
// position, preventing black bars from appearing around modal dialogs.
func placeOverlayOnBackground(canvas string, overlay string, bgColor string, width, height int) string {
	overlayLines := strings.Split(strings.TrimSuffix(overlay, "\n"), "\n")
	canvasLines := strings.Split(canvas, "\n")

	startY := (height - len(overlayLines)) / 2
	if startY < 0 {
		startY = 0
	}

	r, g, b := parseHex(bgColor)
	bgSeq := fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)

	for i, ol := range overlayLines {
		yi := startY + i
		if yi >= len(canvasLines) {
			break
		}
		olWidth := lipgloss.Width(ol)
		startX := (width - olWidth) / 2
		if startX < 0 {
			startX = 0
		}
		rightLen := width - startX - olWidth
		if rightLen < 0 {
			rightLen = 0
		}

		leftPad := ""
		if startX > 0 {
			leftPad = bgSeq + strings.Repeat(" ", startX)
		}
		rightPad := ""
		if rightLen > 0 {
			rightPad = bgSeq + strings.Repeat(" ", rightLen)
		}

		canvasLines[yi] = leftPad + ol + rightPad
	}

	return strings.Join(canvasLines, "\n")
}

func parseHex(hex string) (int, int, int) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, 0, 0
	}
	r, _ := strconv.ParseInt(hex[0:2], 16, 32)
	g, _ := strconv.ParseInt(hex[2:4], 16, 32)
	b, _ := strconv.ParseInt(hex[4:6], 16, 32)
	return int(r), int(g), int(b)
}

func (m *appModel) effectiveTheme() Theme {
	t := m.theme
	if !m.settings.ShowBorders() {
		t.Border = t.Background
	}
	return t
}

func (m *appModel) renderHeader(t Theme) string {
	title := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Text)).
		Bold(true).
		Render("hostveil")

	score := lipgloss.NewStyle().
		Foreground(lipgloss.Color(t.Accent)).
		Render(fmtScore(m.scanResult))

	headerStyle := lipgloss.NewStyle().
		Background(lipgloss.Color(t.Surface)).
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 2).
		Width(m.width)

	return headerStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, title, "   ", score))
}

func (m *appModel) renderFooter(t Theme) string {
	nav := " [1] Overview  [2] Findings  [3] History "
	hint := " [?] Help  [q] Quit "
	if m.width < 80 {
		nav = " [1] Ovw  [2] Fnd  [3] Hist "
		hint = " [?] [q] "
	}

	style := lipgloss.NewStyle().
		Background(lipgloss.Color(t.Surface)).
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 2).
		Width(m.width)

	return style.Render(lipgloss.JoinHorizontal(lipgloss.Center, nav, hint))
}

func fmtScore(r *domain.ScanResult) string {
	return fmt.Sprintf("Score: %d (%s)  |  %d findings", r.ScoreReport.Overall, r.ScoreReport.Grade(), r.TotalFindings())
}
