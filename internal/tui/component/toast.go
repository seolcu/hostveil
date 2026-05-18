package component

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Type int

const (
	Info Type = iota
	Success
	Warning
	Error
)

type Toast struct {
	message   string
	toastType Type
	visible   bool
	expiresAt time.Time
}

func NewToast() *Toast {
	return &Toast{}
}

func (t *Toast) Show(msg string, typ Type, duration time.Duration) tea.Cmd {
	t.message = msg
	t.toastType = typ
	t.visible = true
	t.expiresAt = time.Now().Add(duration)
	return tea.Tick(duration, func(_ time.Time) tea.Msg {
		return expiredMsg{}
	})
}

type expiredMsg struct{}

func (t *Toast) Update(msg tea.Msg) {
	switch msg.(type) {
	case expiredMsg:
		t.visible = false
	}
}

func (t *Toast) Render(bg, fg, card string, width int) string {
	if !t.visible {
		return ""
	}

	color := fg
	switch t.toastType {
	case Success:
		color = "#73daca"
	case Warning:
		color = "#e0af68"
	case Error:
		color = "#f7768e"
	}

	style := lipgloss.NewStyle().
		Background(lipgloss.Color(card)).
		Foreground(lipgloss.Color(color)).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(color)).
		Padding(0, 2).
		MaxWidth(width)

	return style.Render(fmt.Sprintf(" %s ", t.message))
}
