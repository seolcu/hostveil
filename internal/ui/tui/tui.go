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
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/seolcu/hostveil/internal/core"
	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

type mode int

const (
	modeScanning mode = iota
	modeList
	modeDetail
	modePreview
	// modeApplying is shown between confirming a fix (single or batch) and
	// the engine's answer. See applyLabel/applyStartedAt/applyElapsed below.
	modeApplying
	modeMessage
	modeHistory
	modeRollbackConfirm
	// modeForceConfirm is shown when a rollback was declined because the
	// file changed after the fix wrote it. It is its own mode rather than a
	// message because the answer is destructive and one-way.
	modeForceConfirm
	modeTheme
	// modeLayout is the arrangement picker.
	modeLayout
	// modeExport is the export-format picker, and modeExportPath is the
	// free-text destination path typed after a format is chosen.
	modeExport
	modeExportPath

	// modeCount bounds the enum so a test can walk every mode instead of
	// listing them.
	//
	// The list was written out by hand and fell two behind: the frame test
	// called itself "the regression net for the whole composer" while
	// covering eight of ten, and modeForceConfirm — the screen shown when a
	// rollback is declined because the file changed — was never rendered at
	// any terminal size by any test. Keep this last.
	modeCount
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

	// scanPlan is the domains this scan will run, asked of the engine before
	// it starts, and scanState is where each of them has got to. Together
	// they are the denominator and the rows: the events say what has
	// happened and never what is left, so a screen built from events alone
	// can count upwards and cannot draw a bar.
	//
	// scanPlan is empty when there is no engine to ask — every model built
	// as a bare struct literal in the tests — and the screen then falls back
	// to the domains it has heard about, which is what it drew before.
	scanPlan  []model.Source
	scanState map[model.Source]model.ScanState
	// scanStartedAt is when this scan began and scanElapsed is how long ago
	// that was, refreshed by the ticker. The elapsed figure is stored rather
	// than read at render time on purpose: View must be a pure function of
	// the model, and a clock read inside it would make two renders of one
	// state differ.
	scanStartedAt time.Time
	scanElapsed   time.Duration

	// applyLabel names what is being applied — the finding's title for a
	// single fix, a count for a batch — and applyStartedAt/applyElapsed are
	// scanStartedAt/scanElapsed's counterpart for modeApplying, advanced by
	// the same ticker. There is no per-item count the way scanning has a
	// domain plan: ApplyFix and ApplyBatch each return one result with
	// nothing emitted while they run, so the elapsed clock is the only
	// signal modeApplying has that the wait is not hung — see applyingRows.
	applyLabel     string
	applyStartedAt time.Time
	applyElapsed   time.Duration

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

	// Temporary, and goes with the layout picker. layout is the arrangement
	// ID; the zero value renders as the shipped one, which is what keeps every
	// bare struct literal in the tests drawing the default. rowOffset is the
	// lanes arrangement's scroll position, which counts rendered rows rather
	// than findings because its headings are rows too.
	layout       string
	layoutCursor int
	layoutPrev   string
	rowOffset    int
	saveLayout   func(string) error

	// Export picker + free-text path input. exportCursor indexes
	// core.ExportFormats(); exportFormat is fixed once the picker's Enter
	// carries the model into modeExportPath. exportPath is a rune buffer
	// rather than a string because every keystroke inserts or deletes at
	// exportPathCursor, and Go strings are not mutated in place.
	exportCursor     int
	exportFormat     string
	exportPath       []rune
	exportPathCursor int
	exportPrev       mode // modeList or modeDetail, restored on cancel
	saveExport       func(format, path string, data []byte) error

	// gl is which symbol set the screen draws from. The zero value is
	// glyph.Plain, so a model built as a bare struct literal — which is how
	// every layout and frame test builds one — renders what hostveil has
	// always rendered.
	gl glyph.Set
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

// ExportOpts carries the export write path into the TUI, on the same
// pattern as ThemeOpts and LayoutOpts and for the same reason: writing the
// rendered report to disk needs platform.WriteFileAtomic's atomic-write and
// elevation-aware ownership handling, which lives in cmd/hostveil, and the
// layering test forbids this package from doing that itself.
type ExportOpts struct {
	Save func(format, path string, data []byte) error
}

// Opts is everything the TUI is told before it starts. It is one struct
// rather than three parameters because the third would have been the one
// that tipped the signature into being read wrong at a call site.
type Opts struct {
	Theme  ThemeOpts
	Layout LayoutOpts
	Export ExportOpts
	// Glyphs is which symbol set to draw from. It has no Save callback
	// because there is no picker for it: what a terminal's font can draw is
	// a fact about the terminal, set once with --glyphs or HOSTVEIL_GLYPHS
	// and remembered by whoever resolved it.
	Glyphs glyph.Set
}

// New builds the TUI model around an engine. ctx cancels in-flight scans and
// fixes when the process is interrupted.
//
// Opts.Layout is temporary and goes with the picker; an unknown or empty ID
// resolves to the shipped arrangement rather than failing, because a stale
// preference is not worth refusing to start over.
func New(ctx context.Context, engine *core.Engine, opts Opts) tea.Model {
	m := &appModel{
		ctx: ctx, engine: engine, mode: modeScanning, status: "Scanning…", selected: map[string]bool{},
		th: opts.Theme.Initial, saveTheme: opts.Theme.Save,
		saveLayout: opts.Layout.Save, saveExport: opts.Export.Save, gl: opts.Glyphs,
	}
	if l, ok := LookupLayout(opts.Layout.Initial); ok {
		m.layout = l.ID
	}
	return m
}

// runCtx is the context every engine call from the TUI runs under.
//
// It exists because appModel is also built as a bare struct literal — the
// layout and frame tests do it for every mode — and such a model has no
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
// refreshFromEngine re-reads the engine's authoritative report.
//
// Every message that changes the host has to end here: the engine has already
// marked the finding fixed (or un-marked it, after a rollback) and rescored,
// and the list is drawn from m.report. A handler that forgets leaves the
// screen showing a finding the engine knows is gone — no error, no log, just
// a list that is quietly one round out of date.
//
// It was written out three times, which is three chances for a fourth
// message to be added without it.
func (m *appModel) refreshFromEngine() {
	if cur, ok := m.engine.Current(); ok {
		m.report = cur
		m.rebuildActive()
	}
}

func (m *appModel) rebuildActive() {
	m.active = m.report.Select(m.filter)
	m.cursor = clamp(m.cursor, 0, len(m.active)-1)
}

// Run starts the TUI event loop.
func Run(ctx context.Context, engine *core.Engine, opts Opts) error {
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

// elapsedTickMsg advances the elapsed clock on whichever screen is showing
// one — scanning or applying. One message and one ticker for both, because
// it is the same clock answering the same question ("is it hung?") in each:
// duplicating it per mode would be the same code twice.
type elapsedTickMsg struct{}

// elapsedTick is how often the elapsed figure is refreshed. A second,
// because that is the resolution the figure is shown at — a faster tick
// would redraw the screen without changing a character on it.
const elapsedTick = time.Second

func tickElapsed() tea.Cmd {
	return tea.Tick(elapsedTick, func(time.Time) tea.Msg { return elapsedTickMsg{} })
}

// startScan wires the halves together: the scan itself, the event waiter, and
// the clock.
//
// The plan is asked of the engine before anything runs. Nothing else can
// supply it — a checker announces itself when it starts, so a screen built
// from the events alone knows the domains that have begun and not the ones
// still queued, and a list that grows as the scan proceeds is a worse answer
// to "is this hung" than no list at all.
func (m *appModel) startScan() tea.Cmd {
	m.scanDone, m.scanRunning = 0, map[model.Source]bool{}
	m.scanPlan, m.scanState = nil, map[model.Source]model.ScanState{}
	if m.engine != nil {
		// The plan is the list of rows; the state map is only what has been
		// heard since. Seeding the map with ScanPending would be seeding it
		// with the zero value, which is what a missing key already reads as —
		// and it would also make the screen draw a full list from a stale map
		// if the plan were ever lost, hiding exactly the failure the plan
		// exists to prevent.
		m.scanPlan = m.engine.PlannedDomains(core.ScanOptions{})
	}
	m.scanStartedAt, m.scanElapsed = time.Now(), 0
	m.scanCh = make(chan model.ScanEvent, scanEventBuffer)
	return tea.Batch(scanCmd(m.runCtx(), m.engine, m.scanCh), waitForScanEvent(m.scanCh), tickElapsed())
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
	if m.scanState == nil {
		m.scanState = map[model.Source]model.ScanState{}
	}
	if ev.State == model.ScanRunning {
		m.scanRunning[ev.Source] = true
	} else if m.scanRunning[ev.Source] {
		delete(m.scanRunning, ev.Source)
		m.scanDone++
	}
	// The state is recorded for every event including the ones that arrive
	// for a domain the plan does not name — the plan is empty when there is
	// no engine to ask, and the screen falls back to what it has heard.
	m.scanState[ev.Source] = ev.State
	m.status = m.scanStatus()
}

// scanDomains is what the scanning screen draws a row for: the plan when
// there is one, and otherwise the domains that have announced themselves.
//
// The fallback keeps registry order out of it — a scan whose plan is unknown
// is one the tests built by hand, and sorting by label is the only stable
// order available.
func (m *appModel) scanDomains() []model.Source {
	if len(m.scanPlan) > 0 {
		return m.scanPlan
	}
	out := make([]model.Source, 0, len(m.scanState))
	for src := range m.scanState {
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label() < out[j].Label() })
	return out
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

type exportedMsg struct {
	path string
	err  error
}

// exportCmd renders the current report in format and hands the bytes to
// save — the injected, elevation-aware write path (see ExportOpts).
func exportCmd(e *core.Engine, r model.Report, format, path string, save func(string, string, []byte) error) tea.Cmd {
	return func() tea.Msg {
		data, _, _, err := e.Export(r, format)
		if err != nil {
			return exportedMsg{err: err}
		}
		if save != nil {
			err = save(format, path, data)
		}
		return exportedMsg{path: path, err: err}
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

	case elapsedTickMsg:
		// The clock stops with the screen. Re-arming only while the mode it
		// belongs to is showing is what keeps a finished run from redrawing
		// the findings list once a second forever, and it is also why the
		// elapsed figure is stored: View reads it, never the clock, so two
		// renders of one state are identical whatever the wall time between
		// them.
		switch m.mode {
		case modeScanning:
			m.scanElapsed = time.Since(m.scanStartedAt)
			return m, tickElapsed()
		case modeApplying:
			m.applyElapsed = time.Since(m.applyStartedAt)
			return m, tickElapsed()
		default:
			return m, nil
		}

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
			m.status = m.applySummary(msg.outcome)
			m.refreshFromEngine()
		}
		m.mode = modeMessage
		return m, nil

	case exportedMsg:
		if msg.err != nil {
			m.status = "Export failed: " + msg.err.Error()
		} else {
			m.status = "Exported to " + msg.path
		}
		m.mode = modeMessage
		return m, nil

	case batchAppliedMsg:
		m.status = m.batchSummary(msg.outcome)
		m.refreshFromEngine()
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
		m.status = m.rollbackSummary(msg.outcome)
		m.refreshFromEngine()
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
	case modeLayout:
		return m.keyLayout(key)
	case modeExport:
		return m.keyExport(key)
	case modeExportPath:
		return m.keyExportPath(key)
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
	case "m":
		m.markLane()
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
		return m, m.startScan()
	case "h":
		return m, historyCmd(m.engine)
	case "t":
		m.openThemePicker()
	case "l":
		m.openLayoutPicker()
	case "e":
		m.openExportPicker()
	}
	return m, nil
}

// markLane marks every auto-fixable finding at the cursor's severity.
//
// It is the terminal's answer to the lanes arrangement's per-lane button:
// the dashboard's marks the lane's Auto findings and hands them to the batch
// bar rather than applying anything itself, and so does this — `a` is still
// what applies them, and it still goes through the one preview-and-apply
// path. A second route to the same POST is a second place for it to go
// wrong, and the same is true of a second route to ApplyBatch.
func (m *appModel) markLane() {
	if len(m.active) == 0 {
		return
	}
	if m.selected == nil {
		m.selected = map[string]bool{}
	}
	sev := m.active[m.cursor].Severity
	for _, f := range m.active {
		if f.Severity == sev && f.IsAutoFixable() {
			m.selected[f.Key()] = true
		}
	}
}

// openLayoutPicker remembers the current arrangement so cancelling can
// restore it, and starts the cursor on the one in use.
func (m *appModel) openLayoutPicker() {
	m.layout = m.layoutID()
	m.layoutPrev = m.layout
	m.layoutCursor = 0
	for i, l := range Layouts() {
		if l.ID == m.layout {
			m.layoutCursor = i
		}
	}
	m.mode = modeLayout
}

// keyLayout drives the arrangement picker. It mirrors keyTheme, except that
// the choice is not previewed under the cursor: the picker screen is not one
// of the arrangements, so there would be nothing to see. Enter applies it and
// returns to the list, which is where it can be judged.
func (m *appModel) keyLayout(key string) (tea.Model, tea.Cmd) {
	all := Layouts()
	switch key {
	case "up", "k":
		m.layoutCursor = clamp(m.layoutCursor-1, 0, len(all)-1)
	case "down", "j":
		m.layoutCursor = clamp(m.layoutCursor+1, 0, len(all)-1)
	case "enter", "y":
		m.setLayout(all[m.layoutCursor].ID)
		if m.saveLayout != nil {
			// An arrangement that cannot be written down still applies for the
			// rest of the session, for the reason the theme's does: interrupting
			// the user with a modal error over a cosmetic preference costs them
			// more than the lost setting.
			_ = m.saveLayout(m.layout)
		}
		m.mode = modeList
	case "esc", "q", "backspace", "l":
		m.setLayout(m.layoutPrev)
		m.mode = modeList
	}
	return m, nil
}

// setLayout switches the arrangement and drops the scroll positions with it.
// The two are not interchangeable — one counts findings and the other counts
// rendered rows — so carrying either across a switch scrolls the new
// arrangement to somewhere nobody asked for.
func (m *appModel) setLayout(id string) {
	m.layout = id
	m.offset, m.rowOffset = 0, 0
}

// openExportPicker starts the export flow: choose a format, then type a
// destination path. Reachable even on a clean report — an operator with
// nothing to fix may still want to hand a colleague proof of that.
func (m *appModel) openExportPicker() {
	m.exportCursor = 0
	m.exportPrev = m.mode
	m.mode = modeExport
}

// keyExport drives the format picker. Enter carries the choice into
// modeExportPath rather than exporting immediately — a format with no
// destination is not yet a complete request.
func (m *appModel) keyExport(key string) (tea.Model, tea.Cmd) {
	formats := core.ExportFormats()
	switch key {
	case "up", "k":
		m.exportCursor = clamp(m.exportCursor-1, 0, len(formats)-1)
	case "down", "j":
		m.exportCursor = clamp(m.exportCursor+1, 0, len(formats)-1)
	case "enter", "y":
		if len(formats) == 0 {
			return m, nil
		}
		f := formats[m.exportCursor]
		m.exportFormat = f.ID
		m.exportPath = []rune(defaultExportPath(f))
		m.exportPathCursor = len(m.exportPath)
		m.mode = modeExportPath
	case "esc", "q", "backspace":
		m.mode = m.exportPrev
	}
	return m, nil
}

// keyExportPath drives the free-text destination field — hand-rolled rather
// than a general-purpose text-input component, since the whole need is a
// single-line path buffer with basic editing. A rune slice rather than a
// string because every keystroke inserts or deletes at exportPathCursor.
func (m *appModel) keyExportPath(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.mode = modeExport
	case "enter":
		if len(m.exportPath) == 0 {
			return m, nil // no default substituted; the field just stays open
		}
		path := string(m.exportPath)
		m.mode = modeApplying
		m.applyLabel = "Exporting " + m.exportFormat + "…"
		m.applyStartedAt, m.applyElapsed = time.Now(), 0
		return m, tea.Batch(exportCmd(m.engine, m.report, m.exportFormat, path, m.saveExport), tickElapsed())
	case "backspace":
		if m.exportPathCursor > 0 {
			m.exportPath = append(m.exportPath[:m.exportPathCursor-1], m.exportPath[m.exportPathCursor:]...)
			m.exportPathCursor--
		}
	case "delete":
		if m.exportPathCursor < len(m.exportPath) {
			m.exportPath = append(m.exportPath[:m.exportPathCursor], m.exportPath[m.exportPathCursor+1:]...)
		}
	case "left":
		m.exportPathCursor = clamp(m.exportPathCursor-1, 0, len(m.exportPath))
	case "right":
		m.exportPathCursor = clamp(m.exportPathCursor+1, 0, len(m.exportPath))
	case "home":
		m.exportPathCursor = 0
	case "end":
		m.exportPathCursor = len(m.exportPath)
	default:
		// bubbletea reports named keys ("up", "enter", "ctrl+a", ...) as
		// multi-rune strings, so len==1 is what excludes them and admits an
		// ordinary printable character.
		r := []rune(key)
		if len(r) == 1 && r[0] >= 0x20 {
			m.exportPath = append(m.exportPath[:m.exportPathCursor],
				append([]rune{r[0]}, m.exportPath[m.exportPathCursor:]...)...)
			m.exportPathCursor++
		}
	}
	return m, nil
}

// defaultExportPath is the path the field starts pre-filled with — the
// current directory, which is where an interactive user is already
// sitting, and every character of it stays editable.
func defaultExportPath(f core.FormatInfo) string {
	return "hostveil-report-" + time.Now().Format("2006-01-02") + "." + f.Ext
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
	if !f.IsAutoFixable() {
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
		sel = m.report.AutoFixable(m.filter)
	}
	if len(sel) == 0 {
		m.status = "No auto-fixable findings to apply."
		m.mode = modeMessage
		return nil
	}
	m.mode = modeApplying
	m.applyLabel = fmt.Sprintf("%d finding(s)", len(sel))
	m.applyStartedAt, m.applyElapsed = time.Now(), 0
	return tea.Batch(batchCmd(m.runCtx(), m.engine, sel), tickElapsed())
}

// presentSources lists the distinct sources among active findings, sorted,
// so the domain filter only cycles through domains that actually appear.
func (m *appModel) presentSources() []model.Source {
	seen := map[model.Source]bool{}
	var out []model.Source
	for _, f := range m.report.Findings {
		if !f.Active() || seen[f.Source] {
			continue
		}
		seen[f.Source] = true
		out = append(out, f.Source)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// cycleSeverity advances the minimum-severity filter: off → the most severe
// level → each one below it → off.
//
// It walks model.AllSeverities rather than naming the levels, which is what
// it used to do. A hand-written chain has to be edited every time the scale
// changes, and the failure of forgetting is a level the filter simply skips
// — invisible, because the key still appears to work.
func cycleSeverity(cur *model.Severity) *model.Severity {
	levels := model.AllSeverities()
	if len(levels) == 0 {
		return nil
	}
	if cur == nil {
		return &levels[0]
	}
	for i, s := range levels {
		if s == *cur && i+1 < len(levels) {
			return &levels[i+1]
		}
	}
	return nil
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
		f := m.active[m.cursor]
		m.mode = modeApplying
		m.applyLabel = f.Title
		m.applyStartedAt, m.applyElapsed = time.Now(), 0
		return m, tea.Batch(applyCmd(m.runCtx(), m.engine, f, m.previewAction), tickElapsed())
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

// The three summaries below are methods rather than package functions so they
// can reach the glyph set. As functions they could not, so each wrote a
// literal "✓" — and with --glyphs nerd every other tick on the screen was a
// patched glyph while these three were not, which is the drift internal/glyph
// exists to make impossible.
//
// Each returns lines rather than one sentence. They used to concatenate
// clauses into a paragraph, which the message screen then word-wrapped: the
// result broke wherever the column happened to fall ("You may need to /
// restart 'redis'."), and four separate facts — what happened, what it cost,
// how to undo it, what to restart — read as one run-on remark. They are
// separate facts, so they are separate lines.

func (m *appModel) applySummary(o model.FixOutcome) string {
	lines := []string{m.gl.Of(glyph.OK) + " Fix applied.", ""}
	lines = append(lines, fmt.Sprintf("New score: %d/100", o.NewScore.Overall))
	if o.CheckpointID != "" {
		// The checkpoint ID used to be printed here, which was a dead end:
		// acting on it meant quitting to the CLI. Point at the history
		// screen instead, where it can be rolled back in place.
		lines = append(lines, "Press h to undo it.")
	}
	if o.RestartHint != "" {
		lines = append(lines, "", m.gl.Of(glyph.Warning)+" You may need to restart '"+o.RestartHint+"'.")
	}
	if o.VerifyMessage != "" {
		lines = append(lines, "", o.VerifyMessage)
	}
	return strings.Join(lines, "\n")
}

func (m *appModel) rollbackSummary(o model.RollbackOutcome) string {
	files := "files"
	if len(o.RestoredFiles) == 1 {
		files = "file"
	}
	lines := []string{
		m.gl.Of(glyph.OK) + " Rolled back.", "",
		fmt.Sprintf("Restored %d %s", len(o.RestoredFiles), files),
		fmt.Sprintf("New score: %d/100", o.NewScore.Overall),
	}
	if o.RestartService != "" {
		lines = append(lines, "", m.gl.Of(glyph.Warning)+" You may need to restart '"+o.RestartService+"'.")
	}
	return strings.Join(lines, "\n")
}

func (m *appModel) batchSummary(o model.BatchOutcome) string {
	// The claim comes from the engine; this adds only the tick and the one
	// thing that is genuinely local — which key reaches the history view.
	// The fixes that did land are already on the host with checkpoints
	// waiting there, and an operator who thinks the batch completed has no
	// reason to go looking.
	lines := []string{m.gl.Of(glyph.OK) + " " + o.Message}
	if o.Interrupted {
		lines = append(lines, "", "Press h to see what was applied.")
	}
	return strings.Join(lines, "\n")
}
