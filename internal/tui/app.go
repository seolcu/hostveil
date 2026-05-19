package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/export"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/tui/component"
)

var resetSeq = regexp.MustCompile(`\x1b\[0m`)
var bgResetSeq = regexp.MustCompile(`\x1b\[49m`)

type screen int

const (
	screenDashboard screen = iota
	screenFindings
	screenReport
)

type appModel struct {
	currentScreen screen
	width         int
	height        int
	scanResult    *domain.ScanResult
	tick          int
	keys          keyMap

	theme       Theme
	overview    *overviewModel
	findings    *findingsModel
	history     *historyModel
	settings    *settingsModel
	help        *helpModel

	toast   *component.Toast
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
		Quit:   key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit")),
		Filter: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reset filters")),
	}
}

func NewApp(result *domain.ScanResult) *appModel {
	settings := newSettingsModel()
	adapterNames := make([]string, len(result.Metadata.Adapters))
	for i, a := range result.Metadata.Adapters {
		adapterNames[i] = a.Name
	}
	settings.SetAdapters(adapterNames)

	return &appModel{
		currentScreen: screenDashboard,
		scanResult:    result,
		keys:          defaultKeyMap(),
		theme:         DefaultTheme(),
		overview:      &overviewModel{},
		findings:      newFindingsModel(result.Findings),
		history:       &historyModel{},
		settings:      settings,
		help:          &helpModel{},
		toast:         component.NewToast(),
	}
}

func (m *appModel) Init() tea.Cmd {
	return nil
}

func (m *appModel) showToast(msg string) tea.Cmd {
	return m.toast.Show(msg, component.Success, 3*time.Second)
}

func (m *appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case component.ExpiredMsg:
		m.toast.Update(msg)

	case tea.KeyMsg:
		s := msg.String()

		// Global overlays
		if m.help.show {
			if s == "?" || s == "esc" {
				m.help.Toggle()
				return m, nil
			}
		}
		if m.settings.IsOpen() {
			if s == "s" || s == "esc" {
				m.settings.Toggle()
				return m, nil
			}
			if s == "enter" {
				format := m.settings.CurrentExportFormat()
				msg := doExport(m.scanResult, format)
				m.settings.Toggle()
				return m, m.showToast(msg)
			}
			oldTheme := m.settings.themeName
			m.settings.Update(s)
			if m.settings.themeName != oldTheme {
				m.theme = GetTheme(m.settings.themeName)
			}
			return m, nil
		}

		switch {
		case key.Matches(msg, m.keys.Quit) && !m.settings.IsOpen():
			return m, tea.Quit
		case s == "?":
			m.help.Toggle()
		case s == "1":
			m.currentScreen = screenDashboard
		case s == "2":
			m.currentScreen = screenFindings
		case s == "3":
			m.currentScreen = screenReport
		case s == "s" && m.currentScreen != screenFindings:
			m.settings.Toggle()
		case s == "r" || s == "R":
			m.findings.resetFilters()
		case s == "h" && m.currentScreen == screenDashboard:
			// Host triage: switch to findings filtered to host scope
			m.currentScreen = screenFindings
			m.findings.hostTriageMode = true
			m.findings.scopeFilter = "host"
			m.findings.applyFilters()
		case s == "p" && m.currentScreen == screenFindings && m.findings.selected < len(m.findings.list):
			f := m.findings.list[m.findings.selected]
			if f.IsFixable() {
				if m.findings.showFixPreview {
					m.findings.showFixPreview = false
					m.findings.showDetail = true
				} else {
					m.findings.fixPreviewContent = fix.PreviewAnyFinding(f,
						m.scanResult.Metadata.ComposeFile,
						m.scanResult.Findings)
					m.findings.showFixPreview = true
					// Compute backup path for preview
					if f.Source == domain.SourceNativeCompose && m.scanResult.Metadata.ComposeFile != "" {
						eng := fix.NewEngine(m.scanResult.Metadata.ComposeFile, m.scanResult.Findings)
						if plan, err := eng.Preview(); err == nil {
							m.findings.fixBackupPath = plan.BackupPath
						}
					}
				}
			}
		case s == "a" && m.currentScreen == screenFindings && m.findings.showFixPreview && m.findings.selected < len(m.findings.list):
			f := m.findings.list[m.findings.selected]
			if f.Source == domain.SourceNativeCompose && m.scanResult.Metadata.ComposeFile != "" {
				eng := fix.NewEngine(m.scanResult.Metadata.ComposeFile, m.scanResult.Findings)
				plan, err := eng.Apply()
				if err != nil {
					return m, m.showToast(fmt.Sprintf("Apply failed: %v", err))
				}
				msg := fmt.Sprintf("Applied %d fixes. Backup: %s",
					len(plan.AutoApplied)+len(plan.ReviewNeeded), plan.BackupPath)
				if plan.BackupPath == "" {
					msg = fmt.Sprintf("Applied %d fixes.", len(plan.AutoApplied)+len(plan.ReviewNeeded))
				}
				m.findings.showFixPreview = false
				m.findings.showDetail = false
				return m, m.showToast(msg)
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
	case screenDashboard:
		body = m.overview.render(m.scanResult, t, m.width, m.height-4)
	case screenFindings:
		body = m.findings.render(t, m.width, m.height-4)
	case screenReport:
		body = m.history.render(m.scanResult, t, m.width, m.height-4)
	}

	footer := m.renderFooter(t)

	toastLine := m.toast.Render(t.Background, t.Success, t.Surface, m.width)
	if toastLine != "" && m.width > 0 && lipgloss.Width(toastLine) > m.width {
		toastLine = truncateStr(toastLine, m.width-4)
	}

	// Pad body so footer stays at terminal bottom
	toastExtra := 0
	if toastLine != "" {
		toastExtra = 1
	}
	totalLines := strings.Count(header, "\n") + 1 + strings.Count(body, "\n") + 1 + strings.Count(footer, "\n") + 1 + toastExtra
	availableLines := m.height
	if totalLines < availableLines {
		body += strings.Repeat("\n", availableLines-totalLines)
	}

	content := lipgloss.JoinVertical(lipgloss.Top, header, body, footer)
	if toastLine != "" {
		content += "\n" + toastLine
	}

	// Wrap entire render in background color, pad each line to full width
	view := applyBackground(content, t.Background, m.width, m.height)

	// Overlays — place centered on the background-filled canvas
	// We do NOT use lipgloss.Place here because its whitespace padding lacks
	// background styling, causing black bars around modals. Instead we
	// replace canvas lines manually with explicit background sequences.
	if m.help.show {
		overlay := m.help.Render(t, m.width, m.height)
		overlay = fixContentBg(overlay, t.Surface)
		view = placeOverlayOnBackground(view, overlay, t.Background, m.width, m.height)
	} else if m.settings.IsOpen() {
		overlay := m.settings.Render(t, m.width, m.height)
		overlay = fixContentBg(overlay, t.Surface)
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
		lineWidth := lipgloss.Width(line)
		if lineWidth < width {
			lines[i] = line + strings.Repeat(" ", width-lineWidth)
		}
	}
	// Parse hex color to RGB
	r, g, b := parseHex(bgColor)
	bgSeq := fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)
	for i, line := range lines {
		lines[i] = bgSeq + line
	}
	full := strings.Join(lines, "\n")

	// Re-apply theme background after every reset or background-reset sequence.
	// lipgloss internally emits ESC[0m and ESC[49m between styled regions,
	// which would reveal the terminal's default background. We interpose our
	// own background color to keep the entire canvas filled.
	full = resetSeq.ReplaceAllString(full, "\x1b[0m"+bgSeq)
	full = bgResetSeq.ReplaceAllString(full, bgSeq)

	return full + "\x1b[49m"
}

// fixContentBg re-applies a background color after every ANSI reset within
// content, preventing terminal default background from showing through.
func fixContentBg(content, bgColor string) string {
	r, g, b := parseHex(bgColor)
	bgSeq := fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b)
	content = resetSeq.ReplaceAllString(content, "\x1b[0m"+bgSeq)
	content = bgResetSeq.ReplaceAllString(content, bgSeq)
	return content
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
	return m.theme
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
		BorderBottom(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Width(m.width)

	return headerStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, title, "   ", score))
}

func (m *appModel) renderFooter(t Theme) string {
	nav := " [1] Dashboard  [2] Findings  [3] Report "
	hint := " [?] Help  [s] Settings  [q] Quit "
	if m.width < 80 {
		nav = " [1] Dsh  [2] Fnd  [3] Rpt "
		hint = " [?] [s] [q] "
	}

	style := lipgloss.NewStyle().
		BorderTop(true).
		BorderForeground(lipgloss.Color(t.Border)).
		Padding(0, 1).
		Width(m.width)

	return style.Render(lipgloss.JoinHorizontal(lipgloss.Center, nav, hint))
}

func fmtScore(r *domain.ScanResult) string {
	return fmt.Sprintf("Score: %d (%s)  |  %d findings", r.ScoreReport.Overall, r.ScoreReport.Grade(), r.TotalFindings())
}

func doExport(r *domain.ScanResult, format string) string {
	var data string
	var err error
	switch format {
	case "json":
		data, err = export.JSON(r, false)
	case "sarif":
		data, err = export.SARIF(r)
	case "markdown":
		data = export.Markdown(r)
	case "html":
		data, err = export.HTML(r)
	}
	if err != nil {
		return fmt.Sprintf("Export failed: %v", err)
	}

	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("hostveil_report_%s.%s", ts, format)
	outPath, err := filepath.Abs(filename)
	if err != nil {
		outPath = filename
	}
	if err := os.WriteFile(outPath, []byte(data), 0644); err != nil {
		return fmt.Sprintf("Export write failed: %v", err)
	}
	return fmt.Sprintf("Exported %s report to %s", strings.ToUpper(format), outPath)
}
