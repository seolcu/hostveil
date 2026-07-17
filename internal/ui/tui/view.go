package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/seolcu/hostveil/internal/model"
)

var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleSel    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("45"))
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("45"))
)

func severityStyle(s model.Severity) lipgloss.Style {
	switch s {
	case model.SeverityCritical:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	case model.SeverityHigh:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	case model.SeverityMedium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	default:
		return styleDim
	}
}

func (m *appModel) View() tea.View {
	var content string
	switch m.mode {
	case modeScanning:
		content = "\n  " + m.status + "\n"
	case modeList:
		content = m.viewList()
	case modeDetail:
		content = m.viewDetail()
	case modePreview:
		content = m.viewPreview()
	case modeMessage:
		content = m.viewMessage()
	}
	return tea.View{Content: content, AltScreen: true}
}

func (m *appModel) header() string {
	score := m.report.Score.Overall
	return styleHeader.Render("hostveil") + "   " +
		styleBold.Render(fmt.Sprintf("Security score: %d/100", score)) + "\n" +
		styleDim.Render(m.scoreAxes()) + "\n"
}

func (m *appModel) scoreAxes() string {
	var parts []string
	for _, ax := range m.report.Score.Axes {
		if !ax.Applicable {
			parts = append(parts, ax.Label+": N/A")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %d", ax.Label, ax.Score))
	}
	return strings.Join(parts, "  ·  ")
}

func (m *appModel) viewList() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")

	if len(m.active) == 0 {
		b.WriteString(styleGreen.Render("  No problems found. Clean.") + "\n")
		b.WriteString(m.footer("r rescan   q quit"))
		return b.String()
	}

	fmt.Fprintf(&b, "%s\n", styleBold.Render(fmt.Sprintf("Findings (%d)", len(m.active))))
	for i, f := range m.active {
		row := fmt.Sprintf("%-9s %-11s %-13s %s",
			strings.ToUpper(f.Severity.String()), f.ID, f.Remediation.Label(), truncate(f.Title, m.width-40))
		if f.Service != "" {
			row += " (" + f.Service + ")"
		}
		if i == m.cursor {
			b.WriteString(styleSel.Render("› "+row) + "\n")
		} else {
			b.WriteString("  " + severityStyle(f.Severity).Render(row) + "\n")
		}
	}
	b.WriteString(m.footer("↑/↓ move   enter details   f fix   r rescan   q quit"))
	return b.String()
}

func (m *appModel) viewDetail() string {
	f := m.active[m.cursor]
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	fmt.Fprintf(&b, "%s %s\n", severityStyle(f.Severity).Render("["+strings.ToUpper(f.Severity.String())+"]"), styleBold.Render(f.Title))
	fmt.Fprintf(&b, "%s\n\n", styleDim.Render(f.ID+"   "+f.Remediation.Label()+serviceTag(f)))
	b.WriteString(wrap(f.Description, min(m.width-4, 76)) + "\n\n")
	if f.HowToFix != "" {
		b.WriteString(styleGreen.Render("How to fix:") + "\n")
		b.WriteString(wrap(f.HowToFix, min(m.width-4, 76)) + "\n")
	}
	hint := "esc back   q list"
	if f.IsFixable() {
		hint = "f apply fix   " + hint
	}
	b.WriteString(m.footer(hint))
	return b.String()
}

func (m *appModel) viewPreview() string {
	var b strings.Builder
	b.WriteString(styleHeader.Render("Fix preview") + "\n")
	fmt.Fprintf(&b, "%s\n\n", styleBold.Render(m.preview.Label))

	if len(m.preview.Actions) > 1 {
		b.WriteString(styleDim.Render("Alternatives (press a number to choose):") + "\n")
		for _, a := range m.preview.Actions {
			marker := "  "
			if a.Index == m.previewAction {
				marker = "› "
			}
			fmt.Fprintf(&b, "%s[%d] %s\n", marker, a.Index, a.Label)
		}
		b.WriteString("\n")
	}

	a := m.preview.Actions[m.previewAction]
	if a.Warning != "" {
		b.WriteString(severityStyle(model.SeverityHigh).Render("⚠  "+a.Warning) + "\n\n")
	}
	switch a.Type {
	case "edit":
		b.WriteString(renderDiff(a.Diff))
	case "exec":
		b.WriteString(styleDim.Render("These commands will run:") + "\n")
		for _, cmd := range a.Commands {
			b.WriteString("  $ " + strings.Join(cmd, " ") + "\n")
		}
	}
	b.WriteString(m.footer("y apply   n cancel"))
	return b.String()
}

func (m *appModel) viewMessage() string {
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n  " + m.status + "\n")
	b.WriteString(m.footer("press any key to continue"))
	return b.String()
}

func (m *appModel) footer(hint string) string {
	return "\n" + styleDim.Render(hint)
}

func renderDiff(diff string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(diff, "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			b.WriteString(styleGreen.Render(line) + "\n")
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			b.WriteString(severityStyle(model.SeverityCritical).Render(line) + "\n")
		default:
			b.WriteString(styleDim.Render(line) + "\n")
		}
	}
	return b.String()
}

func serviceTag(f model.Finding) string {
	if f.Service == "" {
		return ""
	}
	return "   service: " + f.Service
}

func truncate(s string, max int) string {
	if max < 4 || len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func wrap(s string, width int) string {
	if width < 8 {
		width = 8
	}
	words := strings.Fields(s)
	var b strings.Builder
	ll := 0
	for i, w := range words {
		if i > 0 && ll+1+len(w) > width {
			b.WriteString("\n")
			ll = 0
		} else if i > 0 {
			b.WriteString(" ")
			ll++
		}
		b.WriteString(w)
		ll += len(w)
	}
	return b.String()
}
