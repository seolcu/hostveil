package core

import (
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/report"
)

// FormatInfo is core's own copy of a report.Format, so TUI and web can list
// export formats without importing internal/report themselves — the
// layering rule (AGENTS.md: "UIs may import only core, model, theme,
// glyph") holds even though the mechanical layering test only denies four
// specific package names, not a fifth one like internal/report.
type FormatInfo struct {
	ID, Label, Ext string
}

// ExportFormats lists every format Export accepts, in display order. It is
// a package-level function rather than a method — like theme.All() and
// Layouts() — because it needs no engine state, which is what lets a UI's
// format picker be built from a bare model literal the way every other
// picker's fixtures already are.
func ExportFormats() []FormatInfo {
	all := report.All()
	out := make([]FormatInfo, len(all))
	for i, f := range all {
		out[i] = FormatInfo{ID: f.ID, Label: f.Label, Ext: f.Ext}
	}
	return out
}

// Export renders r in the named format ("json", "sarif", "markdown",
// "docx", or "pdf"), returning the bytes, a suggested filename, and the
// MIME type a caller should advertise. It is the one place a UI reaches
// report rendering from — see FormatInfo's comment.
func (e *Engine) Export(r model.Report, formatID string) (data []byte, filename, contentType string, err error) {
	data, f, err := report.Export(r, e.version, formatID)
	if err != nil {
		return nil, "", "", err
	}
	filename = "hostveil-report-" + time.Now().UTC().Format("2006-01-02") + "." + f.Ext
	return data, filename, f.ContentType, nil
}
