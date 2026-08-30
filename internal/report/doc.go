package report

import "time"

// Doc is the shared intermediate representation the Markdown, DOCX, and PDF
// renderers each walk. Building it once, in build.go, is what keeps the
// three of them from separately re-deriving what a report contains — the
// same "one table, many projections" reasoning internal/model already
// applies to its enums, applied here to the report's layout.
type Doc struct {
	Title     string
	Generated time.Time
	Version   string
	// Hostname is best-effort (os.Hostname can fail in a container with no
	// hostname set) and is simply omitted from the rendered header when empty.
	Hostname string
	Sections []Section
}

// Section is one heading and its content. Exactly one of Paragraphs, KV,
// Table, or Findings is normally populated, but a renderer should not assume
// that — render whichever fields are non-empty, in this field order.
type Section struct {
	Heading    string
	Level      int // 1 = top-level, 2 = subsection
	Paragraphs []string
	KV         []KV
	Table      *Table
	Findings   []FindingBlock
}

// KV is one labeled value, used for the score summary and per-finding
// evidence.
type KV struct{ Key, Value string }

// Table is a simple headers-and-rows grid: the score-by-domain and
// domains-scanned tables.
type Table struct {
	Headers []string
	Rows    [][]string
}

// FindingBlock is one finding, rendered in plain language rather than as an
// ID: what it means, how to fix it (or why hostveil won't), and whatever
// evidence the checker recorded.
type FindingBlock struct {
	Title, Severity, Domain, Service string
	Description, HowToFix, WhyNoFix  string
	// FixBenefit and FixSideEffect are the recommended fix's trade-off —
	// model.Finding.FixBenefit/FixSideEffect verbatim — shown together
	// rather than either/or like HowToFix/WhyNoFix, since a fix can have
	// both a real benefit and a real side effect at once. Empty when the
	// finding has no registered fix.
	FixBenefit, FixSideEffect string
	RemediationLabel          string
	Evidence                  []KV
}
