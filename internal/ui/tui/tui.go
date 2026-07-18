// Package tui is hostveil's thin terminal UI. It renders the engine's
// report and forwards user intent (scan, preview, apply) to the engine —
// it contains NO detection, fix, scoring, or rollback logic of its own.
// It imports only core and model, never fix/history/check directly.
package tui

import (
	"context"
	"fmt"
	"sort"
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
	active []model.Finding // report findings after m.filter

	filter   model.Filter    // classification/narrowing (empty = all active)
	selected map[string]bool // finding.Key() → picked for a batch fix

	cursor        int
	offset        int // first visible finding index (list scrolling)
	width, height int
	mode          mode

	preview       model.FixPreview
	previewAction int
	status        string
}

// New builds the TUI model around an engine.
func New(engine *core.Engine) tea.Model {
	return &appModel{engine: engine, mode: modeScanning, status: "Scanning…", selected: map[string]bool{}}
}

// rebuildActive re-derives the visible list from the current report and
// filter, keeping the cursor in range. The single place both scan and fix
// refresh the list through.
func (m *appModel) rebuildActive() {
	m.active = m.report.Select(m.filter)
	m.cursor = clamp(m.cursor, 0, len(m.active)-1)
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

type batchAppliedMsg struct{ outcome model.BatchOutcome }

func batchCmd(e *core.Engine, fs []model.Finding) tea.Cmd {
	return func() tea.Msg {
		return batchAppliedMsg{outcome: e.ApplyBatch(context.Background(), fs)}
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
		m.selected = map[string]bool{} // a fresh scan invalidates old picks
		m.rebuildActive()
		m.offset = 0
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
				m.rebuildActive()
			}
		}
		m.mode = modeMessage
		return m, nil

	case batchAppliedMsg:
		m.status = batchSummary(msg.outcome)
		if cur, ok := m.engine.Current(); ok {
			m.report = cur
			m.rebuildActive()
		}
		m.selected = map[string]bool{}
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
	case " ", "space":
		m.toggleSelect()
	case "a":
		return m, m.startBatch()
	case "esc":
		m.selected = map[string]bool{}
	case "s":
		m.filter.MinSeverity = cycleSeverity(m.filter.MinSeverity)
		m.rebuildActive()
	case "d":
		m.filter.Source = cycleSource(m.filter.Source, m.presentSources())
		m.rebuildActive()
	case "x":
		m.filter.FixableOnly = !m.filter.FixableOnly
		m.rebuildActive()
	case "c":
		m.filter = model.Filter{}
		m.rebuildActive()
	case "r":
		m.mode = modeScanning
		m.status = "Rescanning…"
		return m, scanCmd(m.engine)
	}
	return m, nil
}

// toggleSelect marks/unmarks the current finding for a batch fix. Only
// auto-fixable findings can be batched, so others are left alone.
func (m *appModel) toggleSelect() {
	if len(m.active) == 0 {
		return
	}
	f := m.active[m.cursor]
	if f.Remediation != model.RemediationAuto {
		return
	}
	k := f.Key()
	if m.selected[k] {
		delete(m.selected, k)
	} else {
		m.selected[k] = true
	}
}

// startBatch applies the marked findings, or every active auto-fix when
// nothing is marked (the TUI's "fix all safe").
func (m *appModel) startBatch() tea.Cmd {
	var sel []model.Finding
	if len(m.selected) > 0 {
		for _, f := range m.active {
			if m.selected[f.Key()] {
				sel = append(sel, f)
			}
		}
	} else {
		for _, f := range m.active {
			if f.Remediation == model.RemediationAuto {
				sel = append(sel, f)
			}
		}
	}
	if len(sel) == 0 {
		m.status = "No auto-fixable findings to apply."
		m.mode = modeMessage
		return nil
	}
	return batchCmd(m.engine, sel)
}

// presentSources lists the distinct sources among active findings, sorted,
// so the domain filter only cycles through domains that actually appear.
func (m *appModel) presentSources() []model.Source {
	seen := map[model.Source]bool{}
	var out []model.Source
	for _, f := range m.report.Findings {
		if f.Fixed || seen[f.Source] {
			continue
		}
		seen[f.Source] = true
		out = append(out, f.Source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// cycleSeverity advances the minimum-severity filter: off → Critical → High
// → Medium → Low → off.
func cycleSeverity(cur *model.Severity) *model.Severity {
	next := func(s model.Severity) *model.Severity { return &s }
	switch {
	case cur == nil:
		return next(model.SeverityCritical)
	case *cur == model.SeverityCritical:
		return next(model.SeverityHigh)
	case *cur == model.SeverityHigh:
		return next(model.SeverityMedium)
	case *cur == model.SeverityMedium:
		return next(model.SeverityLow)
	default:
		return nil
	}
}

// cycleSource advances the domain filter through the present sources and
// back to "all" (SourceUnset).
func cycleSource(cur model.Source, present []model.Source) model.Source {
	if cur == model.SourceUnset {
		if len(present) > 0 {
			return present[0]
		}
		return model.SourceUnset
	}
	for i, s := range present {
		if s == cur {
			if i+1 < len(present) {
				return present[i+1]
			}
			return model.SourceUnset
		}
	}
	return model.SourceUnset
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

func batchSummary(o model.BatchOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "✓ Applied %d", len(o.Applied))
	if len(o.Skipped) > 0 {
		fmt.Fprintf(&b, " · skipped %d", len(o.Skipped))
	}
	if len(o.Failed) > 0 {
		fmt.Fprintf(&b, " · failed %d", len(o.Failed))
	}
	fmt.Fprintf(&b, ". New score: %d/100.", o.NewScore.Overall)
	return b.String()
}
