// Package tui is hostveil's thin terminal UI. It renders the engine's
// report and forwards user intent (scan, preview, apply) to the engine —
// it contains NO detection, fix, scoring, or rollback logic of its own.
// It imports only core and model, never fix/history/check directly.
package tui

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/model"
)

type mode int

const (
	modeScanning mode = iota
	modeList
	modeDetail
	modePreview
	modeMessage
)

type appModel struct {
	engine *core.Engine
	report model.Report
	active []model.Finding

	cursor        int
	width, height int
	mode          mode

	preview       model.FixPreview
	previewAction int
	status        string
}

// New builds the TUI model around an engine.
func New(engine *core.Engine) tea.Model {
	return &appModel{engine: engine, mode: modeScanning, status: "Scanning…"}
}

// Run starts the TUI event loop.
func Run(engine *core.Engine) error {
	_, err := tea.NewProgram(New(engine)).Run()
	return err
}

// --- messages ---

type scannedMsg struct{ report model.Report }
type previewMsg struct {
	preview model.FixPreview
	err     error
}
type appliedMsg struct {
	outcome model.FixOutcome
	err     error
}

func scanCmd(e *core.Engine) tea.Cmd {
	return func() tea.Msg { return scannedMsg{report: e.Scan(context.Background(), nil)} }
}

func previewCmd(e *core.Engine, f model.Finding) tea.Cmd {
	return func() tea.Msg {
		p, err := e.PreviewFix(f)
		return previewMsg{preview: p, err: err}
	}
}

func applyCmd(e *core.Engine, f model.Finding, action int) tea.Cmd {
	return func() tea.Msg {
		o, err := e.ApplyFix(context.Background(), f, action)
		return appliedMsg{outcome: o, err: err}
	}
}

// --- tea.Model ---

func (m *appModel) Init() tea.Cmd { return scanCmd(m.engine) }

func (m *appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case scannedMsg:
		m.report = msg.report
		m.active = m.report.Select(model.Filter{})
		m.cursor = clamp(m.cursor, 0, len(m.active)-1)
		m.mode = modeList
		return m, nil

	case previewMsg:
		if msg.err != nil {
			m.status = "Cannot preview: " + msg.err.Error()
			m.mode = modeMessage
			return m, nil
		}
		m.preview = msg.preview
		m.previewAction = 0
		m.mode = modePreview
		return m, nil

	case appliedMsg:
		if msg.err != nil {
			m.status = "Fix failed: " + msg.err.Error()
		} else {
			m.status = applySummary(msg.outcome)
			// Refresh from the engine's authoritative state.
			if cur, ok := m.engine.Current(); ok {
				m.report = cur
				m.active = m.report.Select(model.Filter{})
				m.cursor = clamp(m.cursor, 0, len(m.active)-1)
			}
		}
		m.mode = modeMessage
		return m, nil

	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m *appModel) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.mode {
	case modeList:
		return m.keyList(key)
	case modeDetail:
		switch key {
		case "esc", "q", "backspace":
			m.mode = modeList
		case "f":
			return m, m.startPreview()
		}
	case modePreview:
		return m.keyPreview(key)
	case modeMessage:
		m.mode = modeList
	}
	return m, nil
}

func (m *appModel) keyList(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.cursor = clamp(m.cursor-1, 0, len(m.active)-1)
	case "down", "j":
		m.cursor = clamp(m.cursor+1, 0, len(m.active)-1)
	case "enter":
		if len(m.active) > 0 {
			m.mode = modeDetail
		}
	case "f":
		return m, m.startPreview()
	case "r":
		m.mode = modeScanning
		m.status = "Rescanning…"
		return m, scanCmd(m.engine)
	}
	return m, nil
}

func (m *appModel) keyPreview(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "n", "q":
		m.mode = modeList
	case "y", "enter":
		if len(m.active) == 0 {
			m.mode = modeList
			return m, nil
		}
		return m, applyCmd(m.engine, m.active[m.cursor], m.previewAction)
	default:
		// Number keys pick an alternative for Review fixes.
		if n := int(key[0] - '0'); len(key) == 1 && n >= 0 && n < len(m.preview.Actions) {
			m.previewAction = n
		}
	}
	return m, nil
}

// startPreview issues a preview command for the selected fixable finding.
func (m *appModel) startPreview() tea.Cmd {
	if len(m.active) == 0 {
		return nil
	}
	f := m.active[m.cursor]
	if !f.IsFixable() {
		m.status = fmt.Sprintf("%s is %s — see the guidance in its detail view.", f.ID, f.Remediation.Label())
		m.mode = modeMessage
		return nil
	}
	return previewCmd(m.engine, f)
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func applySummary(o model.FixOutcome) string {
	var b strings.Builder
	b.WriteString("✓ Fix applied. ")
	if o.CheckpointID != "" {
		fmt.Fprintf(&b, "Rollback id: %s. ", o.CheckpointID)
	}
	fmt.Fprintf(&b, "New score: %d/100.", o.NewScore.Overall)
	if o.RestartHint != "" {
		fmt.Fprintf(&b, " You may need to restart '%s'.", o.RestartHint)
	}
	return b.String()
}
