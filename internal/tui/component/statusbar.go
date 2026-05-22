package component

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

type StatusBar struct {
	selectedIdx   int
	totalCount    int
	activeFilters string
	statusText    string
}

func NewStatusBar() *StatusBar {
	return &StatusBar{}
}

func (s *StatusBar) Update(selected, total int, filters string) {
	s.selectedIdx = selected
	s.totalCount = total
	s.activeFilters = filters
}

func (s *StatusBar) SetStatus(text string) {
	s.statusText = text
}

func (s *StatusBar) Render(borderColor, mutedColor, accentColor string, width int) string {
	leftStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(mutedColor)).
		Width(width / 3)

	centerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(mutedColor)).
		Width(width / 3).
		Align(lipgloss.Center)

	rightStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color(accentColor)).
		Width(width / 3).
		Align(lipgloss.Right)

	left := fmt.Sprintf(" %d / %d", s.selectedIdx, s.totalCount)
	center := s.statusText
	if center == "" {
		center = s.activeFilters
	}
	right := ""

	barStyle := lipgloss.NewStyle().
		BorderTop(true).
		BorderForeground(lipgloss.Color(borderColor)).
		Width(width)

	return barStyle.Render(
		lipgloss.JoinHorizontal(lipgloss.Bottom,
			leftStyle.Render(left),
			centerStyle.Render(center),
			rightStyle.Render(right),
		),
	)
}
