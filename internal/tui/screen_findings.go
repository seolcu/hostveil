package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/seolcu/hostveil/internal/domain"
)

func renderFindingsPanel(r *domain.ScanResult, theme Theme, width, height int) string {
	style := lipgloss.NewStyle().
		Width(width).
		Padding(0, 1)

	out := fmt.Sprintf("Findings (%d total)\n\n", r.TotalFindings())

	for _, f := range r.Findings {
		sevColor := f.Severity.Color()
		line := fmt.Sprintf(" [%s] %s — %s", f.Severity.String(), f.Title, f.Service)
		styled := lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor)).Render(line)
		out += styled + "\n"
	}

	return style.Render(out)
}
