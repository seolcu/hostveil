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
	// modeForceConfirm is shown when a rollback was declined because the
	// file changed after the fix wrote it. It is its own mode rather than a
	// message because the answer is destructive and one-way.
	modeForceConfirm
	modeTheme
)

type appModel struct {
	// ctx is cancelled when the process is interrupted. It rides on the model
	// because bubbletea commands are closures with no parameters of their
	// own, and it has to reach Engine.Scan: the TUI puts the terminal in raw
	// mode and reads Ctrl-C as a key, so without a cancellable context a scan
	// started here could not be stopped by any means at all.
	//
	// Read it through runCtx, never directly — a model built as a bare struct
	// literal has none, which is how several tests construct one.
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

	// scanDone counts the domains that have reported a terminal state this
	// scan, and scanRunning names the ones still working.
	//
	// The engine has emitted these events since the progress display was
	// built for the CLI; the TUI passed nil and threw them away, so a scan
	// that takes minutes on a host with many images showed a static
	// "Scanning…" and nothing else. A screen that cannot distinguish "still
	// working" from "hung" is the one place a spinner is not decoration.
	scanDone    int
	scanRunning map[model.Source]bool
	// scanCh is the live scan's event channel, held so Update can re-arm
	// the waiter after each event.
	scanCh chan model.ScanEvent

	// Advisory AI explanation state for the detail view. Cleared whenever
	// the inspected finding changes, so a slow answer cannot land under the
	// wrong finding — explainedMsg also carries the finding's key and is
	// dropped if the user has moved on.
	aiBusy bool
	aiText string
	aiErr  string

	checkpoints []model.Checkpoint // applied-fix log, newest first
	trend       []model.ScorePoint // score of every retained scan, oldest first
	cpCursor    int
	cpOffset    int
	// historyWarning names checkpoints that could not be read, shown above
	// the list rather than instead of it.
	historyWarning string

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

// runCtx is the context every engine call from the TUI runs under.
//
// It exists because appModel is also built as a bare struct literal — the
// layout and frame tests do it for all eight modes — and such a model has no
// context. Before this, a batch fix issued from one of those panicked on a
// nil dereference inside the engine. Falling back to Background keeps the
// zero value renderable and drivable; production always goes through New.
func (m *appModel) runCtx() context.Context {
	if m.ctx == nil {
		return context.Background()
	}
	return m.ctx
}

// clearAI drops any AI explanation state; called whenever the inspected
// finding is about to change.
func (m *appModel) clearAI() {
	m.aiBusy = false
	m.aiText, m.aiErr = "", ""
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

// scanProgressMsg carries one checker's terminal state as it lands.
type scanProgressMsg struct{ event model.ScanEvent }

// scanEventBuffer is deep enough that a checker never blocks handing over
// its result. Ten domains report once each, and the reader is a bubbletea
// command that may be a frame behind; a buffer this size means the send
// never has to wait for it.
const scanEventBuffer = 32

// scanCmd runs a scan and reports it, feeding progress events into ch.
//
// The channel is closed here, by the only goroutine that writes to it, so
// waitForScanEvent's receive ends cleanly when the scan does rather than
// blocking forever on a channel nobody will write to again.
func scanCmd(ctx context.Context, e *core.Engine, ch chan model.ScanEvent) tea.Cmd {
	return func() tea.Msg {
		report := e.Scan(ctx, ch)
		close(ch)
		return scannedMsg{report: report, delta: e.LastDelta()}
	}
}

// waitForScanEvent blocks on one event and re-arms itself, which is how a
// stream reaches a bubbletea model: a Cmd yields exactly one message, so
// continuous progress is a command that returns the next one and asks for
// another. A closed channel yields nil, ending the chain.
func waitForScanEvent(ch chan model.ScanEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return scanProgressMsg{event: ev}
	}
}

// startScan wires both halves together.
func (m *appModel) startScan() tea.Cmd {
	m.scanDone, m.scanRunning = 0, map[model.Source]bool{}
	m.scanCh = make(chan model.ScanEvent, scanEventBuffer)
	return tea.Batch(scanCmd(m.runCtx(), m.engine, m.scanCh), waitForScanEvent(m.scanCh))
}

// noteScanEvent folds one event into the progress state.
//
// Same reading as the CLI renderer: ScanRunning means a checker started,
// and any other state is that checker finishing — Skipped and Degraded are
// outcomes, not failures to report. Counting terminal events rather than
// tracking a total keeps this correct when a scan runs fewer than every
// domain.
func (m *appModel) noteScanEvent(ev model.ScanEvent) {
	if m.scanRunning == nil {
		m.scanRunning = map[model.Source]bool{}
	}
	if ev.State == model.ScanRunning {
		m.scanRunning[ev.Source] = true
	} else if m.scanRunning[ev.Source] {
		delete(m.scanRunning, ev.Source)
		m.scanDone++
	}
	m.status = m.scanStatus()
}

// scanStatus is the line the scanning screen shows.
//
// It names the domains still working rather than the ones finished,
// because the question the screen has to answer is "is this hung, and on
// what" — and on a real host the answer is almost always the CVE scan,
// which can take minutes. Sorted, because map order would make the line
// jitter on every redraw.
func (m *appModel) scanStatus() string {
	verb := "Scanning"
	if m.scanDone > 0 || len(m.scanRunning) > 0 {
		verb = fmt.Sprintf("Scanning (%d done)", m.scanDone)
	}
	if len(m.scanRunning) == 0 {
		return verb + "…"
	}
	names := make([]string, 0, len(m.scanRunning))
	for src := range m.scanRunning {
		names = append(names, src.Label())
	}
	sort.Strings(names)
	return verb + ": " + strings.Join(names, ", ")
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

type explainedMsg struct {
	key string // Finding.Key() of the finding this answers for
	exp model.Explanation
}

// explainCmd asks the engine for an explanation with the advisory AI
// enabled. The engine degrades on its own: no reachable provider comes
// back as AIError, never as a failure.
func explainCmd(ctx context.Context, e *core.Engine, f model.Finding) tea.Cmd {
	return func() tea.Msg {
		return explainedMsg{key: f.Key(), exp: e.Explain(ctx, f, true)}
	}
}

type historyMsg struct {
	checkpoints []model.Checkpoint
	// trend is the score of every retained scan, oldest first. It rides on
	// the history message because it answers the same question from the
	// other side: the checkpoint list says what was changed, the trend says
	// whether it helped.
	trend []model.ScorePoint
	// warning is set when some checkpoints could not be read. The list is
	// still shown; err is for a history that could not be listed at all.
	warning string
	err     error
}
type rolledBackMsg struct {
	outcome model.RollbackOutcome
	err     error
}

func historyCmd(e *core.Engine) tea.Cmd {
	return func() tea.Msg {
		cps, err := e.ListCheckpoints()
		// Unreadable checkpoints leave a usable list behind, so the view still
		// opens and carries the warning rather than replacing the history with
		// an error screen. What is missing cannot be rolled back at all, which
		// is not something to discover only on trying.
		// A trend that cannot be read costs the trend line, not the
		// history screen. The checkpoints are what the operator opened
		// this for, and they are still there.
		trend, _ := e.ScoreHistory()
		if core.IsIncompleteHistory(err) {
			return historyMsg{checkpoints: cps, trend: trend, warning: err.Error()}
		}
		return historyMsg{checkpoints: cps, trend: trend, err: err}
	}
}

func rollbackCmd(e *core.Engine, id string) tea.Cmd {
	return func() tea.Msg {
		o, err := e.Rollback(id)
		return rolledBackMsg{outcome: o, err: err}
	}
}

// forceRollbackCmd restores over the operator's own later edits.
//
// It is separate from rollbackCmd, and reached only from the declined
// screen, because that is the whole safety property: the engine refuses by
// default, and forcing is a second, informed answer to a question the user
// has now been asked. Rollback writes no checkpoint of its own, so this is
// one-way.
func forceRollbackCmd(e *core.Engine, id string) tea.Cmd {
	return func() tea.Msg {
		o, err := e.RollbackForce(id)
		return rolledBackMsg{outcome: o, err: err}
	}
}

// --- tea.Model ---

func (m *appModel) Init() tea.Cmd { return m.startScan() }

func (m *appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case scanProgressMsg:
		// Progress arriving after the report is stale by definition — the
		// scan is over and the list is already drawn. Drop it rather than
		// overwrite the screen the user is now reading.
		if m.mode != modeScanning {
			return m, nil
		}
		m.noteScanEvent(msg.event)
		return m, waitForScanEvent(m.scanCh)

	case scannedMsg:
		m.report = msg.report
		m.delta = msg.delta
		m.selected = map[string]bool{} // a fresh scan invalidates old picks
		m.clearAI()
		m.rebuildActive()
		m.offset = 0
		m.mode = modeList
		return m, nil

	case explainedMsg:
		m.aiBusy = false
		// A slow answer for a finding the user has already left is dropped
		// rather than rendered under whatever is on screen now.
		if m.mode == modeDetail && len(m.active) > 0 && m.active[m.cursor].Key() == msg.key {
			m.aiText, m.aiErr = msg.exp.AI, msg.exp.AIError
		}
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
		m.trend = msg.trend
		m.historyWarning = msg.warning
		m.cpCursor, m.cpOffset = 0, 0
		m.mode = modeHistory
		return m, nil

	case rolledBackMsg:
		if msg.err != nil {
			// A declined rollback is a question, not a failure. The file
			// changed after hostveil wrote it, so restoring the backup
			// would discard whatever was done in between — and rollback
			// keeps no checkpoint of its own, so there is no way back from
			// that. The CLI has said so and offered --force since 3.4;
			// here the answer was "Rollback failed" and a dead end.
			if core.IsExternalEdit(msg.err) {
				m.status = msg.err.Error()
				m.mode = modeForceConfirm
				return m, nil
			}
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
			m.clearAI()
			m.mode = modeList
		case "f":
			return m, m.startPreview()
		case "e":
			if len(m.active) > 0 && !m.aiBusy {
				m.aiBusy = true
				m.aiText, m.aiErr = "", ""
				return m, explainCmd(m.runCtx(), m.engine, m.active[m.cursor])
			}
		}
	case modePreview:
		return m.keyPreview(key)
	case modeHistory:
		return m.keyHistory(key)
	case modeRollbackConfirm:
		return m.keyRollbackConfirm(key)
	case modeForceConfirm:
		return m.keyForceConfirm(key)
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
			m.clearAI()
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
		m.status = "Rescanning…"
		return m, m.startScan()
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

// keyForceConfirm answers the declined rollback. Anything but an explicit
// yes cancels, matching keyRollbackConfirm — for a one-way overwrite of the
// operator's own edits, a stray keypress must never be consent.
func (m *appModel) keyForceConfirm(key string) (tea.Model, tea.Cmd) {
	if key != "y" {
		m.mode = modeList
		return m, nil
	}
	if len(m.checkpoints) == 0 {
		m.mode = modeList
		return m, nil
	}
	return m, forceRollbackCmd(m.engine, m.checkpoints[m.cpCursor].ID)
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
	return batchCmd(m.runCtx(), m.engine, sel)
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
		return m, applyCmd(m.runCtx(), m.engine, m.active[m.cursor], m.previewAction)
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
	if o.VerifyMessage != "" {
		b.WriteString(" " + o.VerifyMessage)
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
	// An interrupted batch and a completed one differ only in this sentence,
	// and the difference matters: the skipped findings were never judged
	// ineligible, they were never reached, and the fixes that did land are
	// already on the host with checkpoints waiting in the history view.
	if o.Interrupted {
		b.WriteString(" Interrupted before the rest were attempted; press h to see what was applied.")
	}
	return b.String()
}
