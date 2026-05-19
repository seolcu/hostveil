package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

type findingsModel struct {
	list     []domain.Finding
	all      []domain.Finding
	selected int
	scroll   int
	detailVP viewport.Model

	// Filters
	severityFilter    string
	sourceFilter      string
	scopeFilter       string
	serviceFilter     string
	remediationFilter string
	sortMode          string

	searchQuery       string
	showSearch        bool
	showDetail        bool
	showFixPreview    bool
	fixPreviewContent string
	hostTriageMode    bool
}

func newFindingsModel(findings []domain.Finding) *findingsModel {
	m := &findingsModel{
		all:      findings,
		selected: 0,
	}
	m.applyFilters()
	return m
}

func (m *findingsModel) applyFilters() {
	m.list = make([]domain.Finding, 0)
	for _, f := range m.all {
		if m.severityFilter != "" && f.Severity.String() != m.severityFilter {
			continue
		}
		if m.sourceFilter != "" && f.Source.String() != m.sourceFilter {
			continue
		}
		if m.scopeFilter != "" && f.Scope.String() != m.scopeFilter {
			continue
		}
		if m.serviceFilter != "" && f.Service != m.serviceFilter {
			continue
		}
		if m.remediationFilter != "" && f.Remediation.String() != m.remediationFilter {
			continue
		}
		if m.searchQuery != "" {
			q := strings.ToLower(m.searchQuery)
			if !strings.Contains(strings.ToLower(f.Title), q) &&
				!strings.Contains(strings.ToLower(f.Description), q) {
				continue
			}
		}
		m.list = append(m.list, f)
	}

	switch m.sortMode {
	case "severity":
	case "source":
		sort.Slice(m.list, func(i, j int) bool {
			return m.list[i].Source.String() < m.list[j].Source.String()
		})
	case "title":
		sort.Slice(m.list, func(i, j int) bool {
			return m.list[i].Title < m.list[j].Title
		})
	}

	if m.selected >= len(m.list) {
		m.selected = 0
	}
}

func (m *findingsModel) Update(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showSearch {
			s := msg.String()
			switch s {
			case "esc":
				m.showSearch = false
				m.searchQuery = ""
				m.applyFilters()
			case "enter":
				m.showSearch = false
			case "backspace":
				if len(m.searchQuery) > 0 {
					runes := []rune(m.searchQuery)
					m.searchQuery = string(runes[:len(runes)-1])
					m.applyFilters()
				}
			default:
				if len(msg.Runes) > 0 {
					m.searchQuery += string(msg.Runes)
					m.applyFilters()
				}
			}
			return
		}

		switch msg.String() {
		case "j", "down":
			if m.showDetail {
				m.detailVP.LineDown(1)
			} else {
				m.selected++
				if m.selected >= len(m.list) {
					m.selected = len(m.list) - 1
				}
			}
		case "k", "up":
			if m.showDetail {
				m.detailVP.LineUp(1)
			} else {
				m.selected--
				if m.selected < 0 {
					m.selected = 0
				}
			}
		case "enter", "l", "right":
			m.showDetail = !m.showDetail
			if m.showDetail && m.selected < len(m.list) {
				f := m.list[m.selected]
				m.detailVP = viewport.New(60, 20)
				m.detailVP.SetContent(formatFindingDetail(&f))
			}
		case "h", "left":
			m.showDetail = false
		case "s":
			m.cycleFilter("severity")
		case "x":
			m.cycleFilter("source")
		case "c":
			m.cycleFilter("scope")
		case "v":
			m.cycleFilter("service")
		case "m":
			m.cycleFilter("remediation")
		case "o":
			m.cycleSort()
		case "R":
			m.resetFilters()
		case "/":
			m.showSearch = true
		}
		if msg.String() == "esc" {
			m.showSearch = false
			m.showDetail = false
			m.searchQuery = ""
			m.applyFilters()
		}
	}
}

func (m *findingsModel) cycleFilter(filter string) {
	switch filter {
	case "severity":
		m.severityFilter = nextCycle(m.severityFilter, []string{"", "critical", "high", "medium", "low"})
	case "source":
		m.sourceFilter = nextCycle(m.sourceFilter, []string{"", "native_compose", "native_host", "trivy", "dockle", "lynis", "gitleaks"})
	case "scope":
		m.scopeFilter = nextCycle(m.scopeFilter, []string{"", "service", "image", "host", "project"})
	case "service":
		m.serviceFilter = nextCycle(m.serviceFilter, []string{"", "unique_services_from_data"})
	case "remediation":
		m.remediationFilter = nextCycle(m.remediationFilter, []string{"", "auto", "review", "manual"})
	}
	m.applyFilters()
}

func (m *findingsModel) cycleSort() {
	m.sortMode = nextCycle(m.sortMode, []string{"severity", "source", "title"})
	m.applyFilters()
}

func (m *findingsModel) resetFilters() {
	m.severityFilter = ""
	m.sourceFilter = ""
	m.scopeFilter = ""
	m.serviceFilter = ""
	m.remediationFilter = ""
	m.sortMode = "severity"
	m.searchQuery = ""
	m.showSearch = false
	m.selected = 0
	m.hostTriageMode = false
	m.showFixPreview = false
	m.fixPreviewContent = ""
	m.applyFilters()
}

func nextCycle(current string, options []string) string {
	for i, o := range options {
		if o == current {
			return options[(i+1)%len(options)]
		}
	}
	return options[0]
}

func formatFindingDetail(f *domain.Finding) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("ID: %s\n", f.ID))
	b.WriteString(fmt.Sprintf("Severity: %s\n", strings.ToUpper(f.Severity.String())))
	b.WriteString(fmt.Sprintf("Axis: %s\n", f.Axis.Label()))
	b.WriteString(fmt.Sprintf("Scope: %s\n", f.Scope.String()))
	b.WriteString(fmt.Sprintf("Source: %s\n", f.Source.String()))
	b.WriteString(fmt.Sprintf("Service: %s\n", f.Service))
	b.WriteString(fmt.Sprintf("Remediation: %s\n\n", f.Remediation.Label()))
	b.WriteString(fmt.Sprintf("Description:\n%s\n\n", f.Description))
	b.WriteString(fmt.Sprintf("Why it's risky:\n%s\n\n", f.WhyRisky))
	b.WriteString(fmt.Sprintf("How to fix:\n%s\n\n", f.HowToFix))

	if len(f.Evidence) > 0 {
		b.WriteString("Evidence:\n")
		for k, v := range f.Evidence {
			b.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
	}

	return b.String()
}

func highlightText(s, query string) string {
	if query == "" {
		return s
	}
	q := strings.ToLower(query)
	lower := strings.ToLower(s)
	var result strings.Builder
	start := 0
	for {
		idx := strings.Index(lower[start:], q)
		if idx == -1 {
			result.WriteString(s[start:])
			break
		}
		result.WriteString(s[start : start+idx])
		result.WriteString("\x1b[7m" + s[start+idx:start+idx+len(q)] + "\x1b[27m")
		start = start + idx + len(q)
	}
	return result.String()
}

func (m *findingsModel) render(theme Theme, width, height int) string {
	if width < 40 {
		return "Terminal too narrow"
	}

	filterBar := m.renderFilterBar(theme, width)

	listWidth := width
	if m.showDetail {
		listWidth = width / 2
	}
	listHeight := height - 2

	var listContent strings.Builder
	listContent.WriteString(filterBar + "\n")

	if len(m.list) == 0 {
		// Centered empty state with icon
		icon := "·"
		msg := "No findings match current filters."
		if m.hostTriageMode {
			icon = "○"
			msg = "No host-level findings detected.\nAll host findings from this scan are service-level."
		} else if len(m.all) == 0 {
			icon = "·"
			msg = "No findings detected."
		}
		help := "Press R to clear all filters"

		padding := strings.Repeat("\n", (listHeight-6)/2)
		iconStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.Border)).
			Render(icon)
		centerMsg := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(msg)
		centerHelp := lipgloss.NewStyle().
			Foreground(lipgloss.Color(theme.TextMuted)).
			Render(help)

		listContent.WriteString(padding)
		listContent.WriteString(lipgloss.PlaceHorizontal(listWidth, lipgloss.Center, iconStyle) + "\n\n")
		listContent.WriteString(lipgloss.PlaceHorizontal(listWidth, lipgloss.Center, centerMsg) + "\n")
		listContent.WriteString(lipgloss.PlaceHorizontal(listWidth, lipgloss.Center, centerHelp))
	} else {
		for i, f := range m.list {
			cursor := " "
			if i == m.selected {
				cursor = ">"
			}

			color := f.Severity.Color()
			icon := severityIcon(f.Severity)
			idxStr := fmt.Sprintf("%2d.", i+1)
			sevLabel := fmt.Sprintf("%s %s", icon, strings.ToUpper(f.Severity.String()))

			// Highlight search match
			title := f.Title
			if m.searchQuery != "" {
				title = highlightText(title, m.searchQuery)
			}
			title = truncateStr(title, listWidth-36)

			line := fmt.Sprintf("%s  %s  %s %s  %s", cursor, idxStr, sevLabel, title, f.Service)

			style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
			if i == m.selected {
				style = style.Bold(true).Background(lipgloss.Color(theme.Surface))
			}

			listContent.WriteString(style.Render(line) + "\n")
		}
	}

	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]

		detailStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(theme.Border)).
			Width(listWidth).
			Padding(0, 1).
			Height(listHeight)

		headerStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(f.Severity.Color())).
			Bold(true)

		detail := ""
		if m.showFixPreview && m.fixPreviewContent != "" {
			sep := "\n" + strings.Repeat("═", listWidth-4) + "\n"
			detail = headerStyle.Render(fmt.Sprintf("Fix Preview: %s", f.Title)) + "\n\n"
			detail += fmt.Sprintf("Current setup:\n")
			detail += m.fixPreviewContent
			detail += sep
		} else {
			sep := "\n" + strings.Repeat("═", listWidth-4) + "\n"
			detail = headerStyle.Render(f.Title) + "\n\n"

			// Metadata in 2-column layout
			metaLeft := fmt.Sprintf("ID: %s\nSeverity: %s\nAxis: %s\nScope: %s\n",
				f.ID,
				lipgloss.NewStyle().Foreground(lipgloss.Color(f.Severity.Color())).Render(strings.ToUpper(f.Severity.String())),
				f.Axis.Label(),
				f.Scope.String())
			metaRight := fmt.Sprintf("Source: %s\nService: %s\nFix: %s",
				f.Source.String(),
				f.Service,
				f.Remediation.Label())
			if f.IsFixable() {
				metaRight += " (press f)"
			}
			metaLeftStyle := lipgloss.NewStyle().Width(listWidth / 2)
			metaRightStyle := lipgloss.NewStyle().Width(listWidth / 2)
			detail += lipgloss.JoinHorizontal(lipgloss.Top,
				metaLeftStyle.Render(metaLeft),
				metaRightStyle.Render(metaRight),
			)

			detail += sep
			if f.Description != "" {
				detail += fmt.Sprintf("Description:\n%s\n\n", f.Description)
			}
			if f.WhyRisky != "" {
				detail += fmt.Sprintf("Why it's risky:\n%s\n\n", f.WhyRisky)
			}
			if f.HowToFix != "" {
				detail += fmt.Sprintf("How to fix:\n%s\n\n", f.HowToFix)
			}
			if len(f.Evidence) > 0 {
				detail += "Evidence:\n"
				for k, v := range f.Evidence {
					detail += fmt.Sprintf("  %s: %s\n", k, v)
				}
			}
		}

		detailPanel := detailStyle.Render(detail)
		listStyle := lipgloss.NewStyle().
			Width(listWidth).
			Height(listHeight)

		return lipgloss.JoinHorizontal(lipgloss.Top,
			listStyle.Render(listContent.String()),
			detailPanel,
		)
	}

	return listContent.String()
}

func naturalSeverity(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return s
}

func naturalSource(s string) string {
	switch s {
	case "native_compose":
		return "Compose"
	case "native_host":
		return "Host"
	}
	return s
}

func naturalScope(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func naturalRemediation(s string) string {
	switch s {
	case "auto":
		return "Auto"
	case "review":
		return "Review"
	case "manual":
		return "Manual"
	}
	return s
}

func (m *findingsModel) renderFilterBar(theme Theme, width int) string {
	var tokens []string
	if m.severityFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Severity: %s", naturalSeverity(m.severityFilter)))
	}
	if m.sourceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Source: %s", naturalSource(m.sourceFilter)))
	}
	if m.scopeFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Scope: %s", naturalScope(m.scopeFilter)))
	}
	if m.serviceFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Service: %s", m.serviceFilter))
	}
	if m.remediationFilter != "" {
		tokens = append(tokens, fmt.Sprintf("Fix: %s", naturalRemediation(m.remediationFilter)))
	}
	if m.sortMode != "" && m.sortMode != "severity" {
		tokens = append(tokens, fmt.Sprintf("Sort: %s ↑", m.sortMode))
	}

	info := fmt.Sprintf("%d/%d", len(m.list), len(m.all))
	if len(tokens) > 0 {
		filterLine := strings.Join(tokens, " | ")
		if len(info)+len(filterLine)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + filterLine
		} else {
			info += "  " + filterLine
		}
	} else {
		info += "  no filters"
	}

	if m.showSearch {
		s := "search: Type to search, Esc to cancel"
		if m.searchQuery != "" {
			s = fmt.Sprintf("search: %s█", m.searchQuery)
		}
		if len(info)+len(s)+7 > width {
			info += "\n" + strings.Repeat(" ", 6) + s
		} else {
			info += " | " + s
		}
	}

	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Width(width)

	return style.Render(info)
}

func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
