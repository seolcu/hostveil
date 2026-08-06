package tui

// This file is the arrangement registry — the terminal half of the one in
// internal/ui/web/layout.go, and the two go together.
//
// Six arrangements of the dashboard were mocked up so one could be chosen,
// and all six were shipped behind a selector so they could be driven against
// a real host rather than argued about from screenshots. **C · Console won
// and is the default.** The other five stay rather than being deleted, which
// is a change of plan and worth saying why: the thing the comparison actually
// showed is that the right arrangement depends on the terminal in front of
// you. The rail costs 25 of 80 columns and pays for itself on a wide one; the
// split pane is the first casualty of a narrow one; lanes are worth their
// three header rows on a host with forty findings and not on a host with
// four. A default answers the common case, and the picker answers the rest.
//
// The IDs, names and order match the dashboard's registry exactly, and
// TestLayoutRegistriesMatchTheDashboard holds that — a picker whose "B" meant
// one thing here and another there would make choosing between them worse
// than useless.
//
// What each arrangement *is* had to be translated rather than copied. A
// browser has an overlay, a scrim and a 1440-column window; a terminal has
// one grid, and its detail view is already a full-screen mode, which is what
// an overlay is. The notes below say what each bet turned into here.

// Layout is one arrangement. ID is what is saved and what the renderer
// branches on, Name is what the picker shows, and Note is the one-line
// description of the bet it makes.
type Layout struct {
	ID   string
	Name string
	Note string
}

// layouts is the registry, in the order the picker lists them: the default
// first, then the alternatives in the order they were proposed.
//
// The letters are kept in the names because that is what the mockups and the
// discussion around them called these, and renaming them now would break
// every reference to "G" or "H" outside this file for no gain. They are not
// the picker's order any more, and that is fine: the first entry is the one
// an operator gets without choosing, which is the ordering that earns its
// place at the top of a list.
var layouts = []Layout{
	{
		ID: "console", Name: "C · Console",
		Note: "A domain rail down the left carrying every score and every coverage gap.",
	},
	{
		ID: "split", Name: "A · Split",
		Note: "Axes strip across the top, findings list, detail beside it when there is room.",
	},
	{
		ID: "triage", Name: "B · Triage",
		Note: "A spoken verdict on top, axes as one spark row, full-width list, detail as a screen.",
	},
	{
		ID: "railverdict", Name: "G · Rail + verdict",
		Note: "The rail and the verdict together, with the detail pane given back to the list.",
	},
	{
		ID: "lanes", Name: "H · Lanes",
		Note: "The split pane kept, the list grouped into severity lanes that each fix themselves.",
	},
	{
		ID: "inline", Name: "I · Inline",
		Note: "No detail pane. One full-width list, and the finding under the cursor opens in place.",
	},
}

// DefaultLayout is what a terminal with no saved choice gets: C · Console,
// the arrangement chosen from the six. It is the rail one because the rail is
// the only place a domain that could not be scanned is both visible and
// explained, and "I could not look" passing for "nothing there" is the
// failure this whole program is built to refuse.
func DefaultLayout() Layout { return layouts[0] }

// Layouts returns the registry in picker order.
func Layouts() []Layout {
	out := make([]Layout, len(layouts))
	copy(out, layouts)
	return out
}

// LookupLayout resolves an ID to its layout. An unknown ID — a stale saved
// preference, most likely — is not an error anywhere: the caller falls back
// to the default rather than refusing to start over a cosmetic choice.
func LookupLayout(id string) (Layout, bool) {
	for _, l := range layouts {
		if l.ID == id {
			return l, true
		}
	}
	return Layout{}, false
}

// LayoutIDs lists every layout ID, for help text and error messages.
func LayoutIDs() []string {
	out := make([]string, 0, len(layouts))
	for _, l := range layouts {
		out = append(out, l.ID)
	}
	return out
}

// LayoutOpts carries the arrangement into the TUI.
//
// Save is a callback rather than a directory for the reason ThemeOpts.Save
// is: the TUI must not know where hostveil keeps its state, because that
// lives in internal/history and the layering test forbids importing it.
type LayoutOpts struct {
	Initial string                // saved layout ID; "" or unknown means the default
	Save    func(id string) error // nil when there is nowhere to persist to
}

// --- what each arrangement turns on ---
//
// These are the terminal's translation of the dashboard's CSS blocks, and
// they are written as one predicate per region rather than a switch per
// renderer so that a layout is described in one place and read in several.

// layoutID is the active arrangement, resolved so the zero value renders as
// the shipped one. Every model built as a bare struct literal — which is how
// the frame and layout tests build one — goes through here.
func (m *appModel) layoutID() string {
	if _, ok := LookupLayout(m.layout); ok {
		return m.layout
	}
	return DefaultLayout().ID
}

func (m *appModel) layoutIs(ids ...string) bool {
	cur := m.layoutID()
	for _, id := range ids {
		if id == cur {
			return true
		}
	}
	return false
}

// wantsRail reports whether this arrangement puts the domain rail beside the
// list. The rail replaces the axes strip where it appears: every number in
// the strip is in the rail, with the reason for each gap attached, so
// keeping both would be saying the same thing twice in the space the list
// wants.
func (m *appModel) wantsRail() bool { return m.layoutIs("console", "railverdict") }

// wantsVerdict reports whether the list is led by a sentence saying what is
// wrong and what to press.
func (m *appModel) wantsVerdict() bool { return m.layoutIs("triage", "railverdict") }

// wantsPane reports whether the finding under the cursor is shown beside the
// list rather than only on `enter`.
func (m *appModel) wantsPane() bool { return m.layoutIs("split", "console", "lanes") }

// wantsLanes reports whether the list is grouped into one section per
// severity, each with its own count and its own batch action.
func (m *appModel) wantsLanes() bool { return m.layoutIs("lanes") }

// wantsInline reports whether the cursor's finding opens in place, in the
// list, instead of in a pane or on its own screen.
func (m *appModel) wantsInline() bool { return m.layoutIs("inline") }

// axesStyle says how the score breakdown is drawn in the header.
type axesStyle int

const (
	axesFull  axesStyle = iota // the wrapped strip: one cell per domain
	axesSpark                  // one row of label/score pairs
	axesNone                   // nothing: the rail carries the same numbers
)

func (m *appModel) axesStyle() axesStyle {
	switch {
	case m.wantsRail():
		return axesNone
	case m.layoutIs("triage", "inline"):
		return axesSpark
	default:
		return axesFull
	}
}
