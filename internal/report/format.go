// Package report renders a completed model.Report into a file an operator
// can read or hand to a colleague, or that another program can ingest.
//
// It depends only on internal/model (and, for JSON/SARIF, internal/clirender
// — which itself depends only on internal/model, so there is no cycle) and
// must never import internal/fix, internal/history, internal/check, or
// internal/compose: those are UI-forbidden packages, and this package is
// reached from internal/core on behalf of every UI.
package report

// Format describes one export format: its stable ID (used in flags, query
// parameters, and file extensions), its human label, and the MIME type a
// consumer should be told it is receiving.
//
// This is the one table every caller resolves a format against — the CLI's
// --format flag, the TUI's picker, and the web dashboard's route — so a
// sixth format only ever needs one new row here.
type Format struct {
	ID          string
	Label       string
	Ext         string
	ContentType string
}

var formats = []Format{
	{ID: "json", Label: "JSON", Ext: "json", ContentType: "application/json"},
	{ID: "sarif", Label: "SARIF", Ext: "sarif", ContentType: "application/sarif+json"},
	{ID: "markdown", Label: "Markdown", Ext: "md", ContentType: "text/markdown; charset=utf-8"},
	{ID: "docx", Label: "Word", Ext: "docx", ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
	{ID: "pdf", Label: "PDF", Ext: "pdf", ContentType: "application/pdf"},
}

// All lists every export format, in the order a picker should offer them.
func All() []Format {
	out := make([]Format, len(formats))
	copy(out, formats)
	return out
}

// Parse resolves a format ID (e.g. "markdown"), reporting false if it names
// none of the formats above.
func Parse(id string) (Format, bool) {
	for _, f := range formats {
		if f.ID == id {
			return f, true
		}
	}
	return Format{}, false
}
