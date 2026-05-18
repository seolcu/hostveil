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
	list       []domain.Finding
	all        []domain.Finding
	selected   int
	scroll     int
	detailVP   viewport.Model

	// Filters
	severityFilter   string // "", "critical", "high", "medium", "low"
	sourceFilter     string
	scopeFilter      string
	serviceFilter    string
	remediationFilter string
	sortMode         string // "severity", "source", "title"

	searchQuery    string
	showSearch     bool
	showDetail     bool
	hostTriageMode bool
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
			m.showSearch = !m.showSearch
			if !m.showSearch {
				m.searchQuery = ""
				m.applyFilters()
			}
		}
		if m.showSearch && msg.String() != "/" && msg.String() != "esc" {
			if msg.String() == "backspace" && len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
			} else if len(msg.String()) == 1 && msg.String() >= " " {
				m.searchQuery += msg.String()
			}
			m.applyFilters()
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

func (m *findingsModel) render(theme Theme, width, height int) string {
	if width < 40 {
		return "Terminal too narrow"
	}

	// Filter status bar
	filterBar := m.renderFilterBar(theme, width)
	m.applyFilters()

	// List
	listWidth := width
	if m.showDetail {
		listWidth = width / 2
	}
	listHeight := height - 3

	var listContent strings.Builder
	listContent.WriteString(filterBar + "\n")

	if len(m.list) == 0 {
		listContent.WriteString("  No findings match current filters.")
	} else {
		for i, f := range m.list {
			cursor := " "
			if i == m.selected {
				cursor = ">"
			}

			color := f.Severity.Color()
			title := truncateStr(f.Title, listWidth-20)
			line := fmt.Sprintf("%s [%s] %s  %s", cursor, strings.ToUpper(f.Severity.String()), title, f.Service)

			style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
			if i == m.selected {
				style = style.Bold(true)
			}

			listContent.WriteString(style.Render(line) + "\n")
		}
	}

	// Detail panel
	if m.showDetail && m.selected < len(m.list) {
		f := m.list[m.selected]

		detailStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(theme.Border)).
			Width(width / 2).
			Padding(0, 1).
			Height(listHeight)

		headerStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color(f.Severity.Color())).
			Bold(true)

		detail := headerStyle.Render(f.Title) + "\n\n"
		detail += fmt.Sprintf("ID: %s\n", f.ID)
		detail += fmt.Sprintf("Severity: %s | Axis: %s\n", strings.ToUpper(f.Severity.String()), f.Axis.Label())
		detail += fmt.Sprintf("Source: %s | Scope: %s\n", f.Source.String(), f.Scope.String())
		if f.Service != "" {
			detail += fmt.Sprintf("Service: %s\n", f.Service)
		}
		detail += fmt.Sprintf("Fix: %s\n\n", f.Remediation.Label())
		detail += fmt.Sprintf("Description:\n%s\n\n", f.Description)
		detail += fmt.Sprintf("Why it's risky:\n%s\n\n", f.WhyRisky)
		if f.HowToFix != "" {
			detail += fmt.Sprintf("How to fix:\n%s\n\n", f.HowToFix)
		}
		if len(f.Evidence) > 0 {
			detail += "Evidence:\n"
			for k, v := range f.Evidence {
				detail += fmt.Sprintf("  %s: %s\n", k, v)
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

func (m *findingsModel) renderFilterBar(theme Theme, width int) string {
	activeFilters := ""
	if m.severityFilter != "" {
		activeFilters += fmt.Sprintf(" sev:%s", m.severityFilter)
	}
	if m.sourceFilter != "" {
		activeFilters += fmt.Sprintf(" src:%s", m.sourceFilter)
	}
	if m.scopeFilter != "" {
		activeFilters += fmt.Sprintf(" scp:%s", m.scopeFilter)
	}
	if m.serviceFilter != "" {
		activeFilters += fmt.Sprintf(" svc:%s", m.serviceFilter)
	}
	if m.remediationFilter != "" {
		activeFilters += fmt.Sprintf(" rem:%s", m.remediationFilter)
	}
	if m.sortMode != "" && m.sortMode != "severity" {
		activeFilters += fmt.Sprintf(" sort:%s", m.sortMode)
	}

	filterInfo := fmt.Sprintf("%d/%d", len(m.list), len(m.all))
	if activeFilters != "" {
		filterInfo += activeFilters
	}

	if m.showSearch {
		filterInfo += fmt.Sprintf("  search: %s█", m.searchQuery)
	}

	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color(theme.TextMuted)).
		Width(width)

	return style.Render(filterInfo)
}

func truncateStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n-1]) + "…"
}
