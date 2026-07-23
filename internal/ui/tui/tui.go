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
	"github.com/seolcu/hostveil/internal/ui/theme"
)

type mode int

const (
	modeScanning mode = iota
	modeList
	modeDetail
	modePreview
	modeMessage
	modeHistory
	modeRollbackConfirm
	modeTheme
)

type appModel struct {
	// ctx is cancelled when the process is interrupted. It rides on the model
	// because bubbletea commands are closures with no parameters of their
	// own, and it has to reach Engine.Scan: the TUI puts the terminal in raw
	// mode and reads Ctrl-C as a key, so without a cancellable context a scan
	// started here could not be stopped by any means at all.
	ctx    context.Context
	engine *core.Engine
	report model.Report
	active []model.Finding // report findings after m.filter

	filter   model.Filter    // classification/narrowing (empty = all active)
	selected map[string]bool // finding.Key() → picked for a batch fix

	cursor        int
	offset        int // first visible finding index (list scrolling)
	width, height int
	mode          mode

	delta         model.Delta // how this scan differs from the previous one
	preview       model.FixPreview
	previewAction int
	status        string

	checkpoints []model.Checkpoint // applied-fix log, newest first
	cpCursor    int
	cpOffset    int

	th          theme.Theme // active color theme; the zero value renders as the default
	st          *styles     // th resolved into lipgloss styles, built on first render
	themeCursor int
	themePrev   theme.Theme        // restored when the picker is cancelled
	saveTheme   func(string) error // nil when there is nowhere to persist to
}

// ThemeOpts carries the color theme into the TUI.
//
// Save records a theme chosen in the picker so the next run starts in it. It
// is a callback rather than a directory because the TUI must not know where
// hostveil keeps its state: that lives in internal/history, which the
// layering test forbids this package from importing. cmd/hostveil, which may
// import it, wires the two together.
type ThemeOpts struct {
	Initial theme.Theme
	Save    func(id string) error
}

// New builds the TUI model around an engine. ctx cancels in-flight scans and
// fixes when the process is interrupted.
func New(ctx context.Context, engine *core.Engine, opts ThemeOpts) tea.Model {
	return &appModel{
		ctx: ctx, engine: engine, mode: modeScanning, status: "Scanning…", selected: map[string]bool{},
		th: opts.Initial, saveTheme: opts.Save,
	}
}

// rebuildActive re-derives the visible list from the current report and
// filter, keeping the cursor in range. The single place both scan and fix
// refresh the list through.
func (m *appModel) rebuildActive() {
	m.active = m.report.Select(m.filter)
	m.cursor = clamp(m.cursor, 0, len(m.active)-1)
}

// Run starts the TUI event loop.
func Run(ctx context.Context, engine *core.Engine, opts ThemeOpts) error {
	_, err := tea.NewProgram(New(ctx, engine, opts)).Run()
	return err
}

// --- messages ---

type scannedMsg struct {
	report model.Report
	delta  model.Delta
}
type previewMsg struct {
	preview model.FixPreview
	err     error
}
type appliedMsg struct {
	outcome model.FixOutcome
	err     error
}

func scanCmd(ctx context.Context, e *core.Engine) tea.Cmd {
	return func() tea.Msg {
		report := e.Scan(ctx, nil)
		return scannedMsg{report: report, delta: e.LastDelta()}
	}
}

func previewCmd(e *core.Engine, f model.Finding) tea.Cmd {
	return func() tea.Msg {
		p, err := e.PreviewFix(f)
		return previewMsg{preview: p, err: err}
	}
}

func applyCmd(ctx context.Context, e *core.Engine, f model.Finding, action int) tea.Cmd {
	return func() tea.Msg {
		o, err := e.ApplyFix(ctx, f, action)
		return appliedMsg{outcome: o, err: err}
	}
}

type batchAppliedMsg struct{ outcome model.BatchOutcome }

func batchCmd(ctx context.Context, e *core.Engine, fs []model.Finding) tea.Cmd {
	return func() tea.Msg {
		return batchAppliedMsg{outcome: e.ApplyBatch(ctx, fs)}
	}
}

type historyMsg struct {
	checkpoints []model.Checkpoint
	err         error
}
type rolledBackMsg struct {
	outcome model.RollbackOutcome
	err     error
}

func historyCmd(e *core.Engine) tea.Cmd {
	return func() tea.Msg {
		cps, err := e.ListCheckpoints()
		return historyMsg{checkpoints: cps, err: err}
	}
}

func rollbackCmd(e *core.Engine, id string) tea.Cmd {
	return func() tea.Msg {
		o, err := e.Rollback(id)
		return rolledBackMsg{outcome: o, err: err}
	}
}

// --- tea.Model ---

func (m *appModel) Init() tea.Cmd { return scanCmd(m.ctx, m.engine) }

func (m *appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case scannedMsg:
		m.report = msg.report
		m.delta = msg.delta
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

	case historyMsg:
		if msg.err != nil {
			m.status = "Cannot read history: " + msg.err.Error()
			m.mode = modeMessage
			return m, nil
		}
		if len(msg.checkpoints) == 0 {
			m.status = "No fixes have been applied yet."
			m.mode = modeMessage
			return m, nil
		}
		m.checkpoints = msg.checkpoints
		m.cpCursor, m.cpOffset = 0, 0
		m.mode = modeHistory
		return m, nil

	case rolledBackMsg:
		if msg.err != nil {
			m.status = "Rollback failed: " + msg.err.Error()
			m.mode = modeMessage
			return m, nil
		}
		m.status = rollbackSummary(msg.outcome)
		// Refresh from the engine, which has already un-marked the finding
		// and rescored, so the restored finding reappears in the list.
		if cur, ok := m.engine.Current(); ok {
			m.report = cur
			m.rebuildActive()
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
	case modeHistory:
		return m.keyHistory(key)
	case modeRollbackConfirm:
		return m.keyRollbackConfirm(key)
	case modeTheme:
		return m.keyTheme(key)
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
		return m, scanCmd(m.ctx, m.engine)
	case "h":
		return m, historyCmd(m.engine)
	case "t":
		m.openThemePicker()
	}
	return m, nil
}

// openThemePicker remembers the current theme so cancelling can restore it,
// and starts the cursor on the theme in use rather than at the top.
func (m *appModel) openThemePicker() {
	// Resolve the zero value first, so "what was active" is a real theme and
	// cancelling restores it rather than blanking the palette.
	m.setTheme(m.th)
	m.themePrev = m.th
	m.themeCursor = 0
	for i, t := range theme.All() {
		if t.ID == m.themePrev.ID {
			m.themeCursor = i
		}
	}
	m.mode = modeTheme
}

// keyTheme drives the picker. Moving the cursor applies the theme
// immediately: the preview *is* the rest of the interface.
func (m *appModel) keyTheme(key string) (tea.Model, tea.Cmd) {
	all := theme.All()
	switch key {
	case "up", "k":
		m.themeCursor = clamp(m.themeCursor-1, 0, len(all)-1)
		m.setTheme(all[m.themeCursor])
	case "down", "j":
		m.themeCursor = clamp(m.themeCursor+1, 0, len(all)-1)
		m.setTheme(all[m.themeCursor])
	case "enter", "y":
		if m.saveTheme != nil {
			// A theme that cannot be written down still applies for the rest
			// of the session. Interrupting the user with a modal error over a
			// cosmetic preference would cost them more than the lost setting.
			_ = m.saveTheme(m.th.ID)
		}
		m.mode = modeList
	case "esc", "q", "backspace", "t":
		m.setTheme(m.themePrev)
		m.mode = modeList
	}
	return m, nil
}

func (m *appModel) keyHistory(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "backspace", "h":
		m.mode = modeList
	case "up", "k":
		m.cpCursor = clamp(m.cpCursor-1, 0, len(m.checkpoints)-1)
	case "down", "j":
		m.cpCursor = clamp(m.cpCursor+1, 0, len(m.checkpoints)-1)
	case "enter", "r":
		if len(m.checkpoints) == 0 {
			return m, nil
		}
		if !m.checkpoints[m.cpCursor].Reversible {
			m.status = "That fix ran a command rather than editing a file, so there is nothing to restore automatically."
			m.mode = modeMessage
			return m, nil
		}
		m.mode = modeRollbackConfirm
	}
	return m, nil
}

func (m *appModel) keyRollbackConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "enter":
		if len(m.checkpoints) == 0 {
			m.mode = modeList
			return m, nil
		}
		return m, rollbackCmd(m.engine, m.checkpoints[m.cpCursor].ID)
	default:
		m.mode = modeHistory
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
	return batchCmd(m.ctx, m.engine, sel)
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
		return m, applyCmd(m.ctx, m.engine, m.active[m.cursor], m.previewAction)
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
		// The checkpoint ID used to be printed here, which was a dead end:
		// acting on it meant quitting to the CLI. Point at the history
		// screen instead, where it can be rolled back in place.
		b.WriteString("Press h to undo it. ")
	}
	fmt.Fprintf(&b, "New score: %d/100.", o.NewScore.Overall)
	if o.RestartHint != "" {
		fmt.Fprintf(&b, " You may need to restart '%s'.", o.RestartHint)
	}
	return b.String()
}

func rollbackSummary(o model.RollbackOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "✓ Rolled back. Restored %d file", len(o.RestoredFiles))
	if len(o.RestoredFiles) != 1 {
		b.WriteString("s")
	}
	fmt.Fprintf(&b, ". New score: %d/100.", o.NewScore.Overall)
	if o.RestartService != "" {
		fmt.Fprintf(&b, " You may need to restart '%s'.", o.RestartService)
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
