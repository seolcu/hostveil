package report

import (
	"bytes"
	"fmt"
	"strings"
)

// pdf renders d as a minimal single-content-stream-per-page PDF using the
// Helvetica/Helvetica-Bold base-14 fonts (no embedding — every reader
// carries these), hand-written rather than pulled from a third-party
// library, for the same reason docx.go is: no pure-Go PDF library found
// during design met "MIT/BSD/Apache, actively maintained, multi-year track
// record" for a tool that ships SBOMs and provenance attestations, and the
// content this report needs — headings, paragraphs, plain key/value and
// tabular text, no images — is well within what a textbook minimal PDF
// writer covers.
const (
	pdfPageW      = 595.0 // A4, points
	pdfPageH      = 842.0
	pdfMargin     = 50.0
	pdfContentW   = pdfPageW - 2*pdfMargin
	pdfBottomStop = pdfMargin
)

func pdf(d Doc) ([]byte, error) {
	b := newPDFBuilder()
	b.heading(1, d.Title)
	sub := "Generated " + d.Generated.Format("2006-01-02 15:04 MST") + " by hostveil " + d.Version
	if d.Hostname != "" {
		sub += " on " + d.Hostname
	}
	b.paragraph(sub, 10, false)
	b.gap()

	for _, sec := range d.Sections {
		b.section(sec)
	}

	return b.write()
}

// ── layout ──────────────────────────────────────────────────────────────

type pdfBuilder struct {
	pages   [][]byte // finished page content streams
	cur     bytes.Buffer
	y       float64
	started bool
}

func newPDFBuilder() *pdfBuilder {
	b := &pdfBuilder{}
	b.newPage()
	return b
}

func (b *pdfBuilder) newPage() {
	if b.started {
		b.pages = append(b.pages, b.cur.Bytes())
	}
	b.cur = bytes.Buffer{}
	b.y = pdfPageH - pdfMargin
	b.started = true
}

// ensure makes sure at least `need` points remain before the bottom margin,
// starting a new page first if not.
func (b *pdfBuilder) ensure(need float64) {
	if b.y-need < pdfBottomStop {
		b.newPage()
	}
}

func (b *pdfBuilder) leading(size float64) float64 { return size * 1.35 }

// line writes one already-fitted line of text at the current cursor and
// advances it. bold selects Helvetica-Bold (F2) over Helvetica (F1).
func (b *pdfBuilder) line(text string, size float64, bold bool) {
	lead := b.leading(size)
	b.ensure(lead)
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(&b.cur, "BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n",
		font, size, pdfMargin, b.y, pdfEscape(text))
	b.y -= lead
}

func (b *pdfBuilder) gap() { b.y -= 8 }

func (b *pdfBuilder) heading(level int, text string) {
	size := map[int]float64{1: 18, 2: 15, 3: 13, 4: 12}[level]
	if size == 0 {
		size = 12
	}
	b.ensure(size + 10)
	if level <= 2 {
		b.gap()
	}
	for _, ln := range wrapPDF(text, true, size, pdfContentW) {
		b.line(ln, size, true)
	}
	b.gap()
}

func (b *pdfBuilder) paragraph(text string, size float64, bold bool) {
	for _, ln := range wrapPDF(text, bold, size, pdfContentW) {
		b.line(ln, size, bold)
	}
}

// kv renders "Key: value", bold key and regular value on one visual block —
// wrapped as its own paragraph since a hand-rolled writer mixing two fonts
// mid-line for a value that may itself wrap adds real complexity for no
// reader-visible benefit here.
func (b *pdfBuilder) kv(key, val string, size float64) {
	b.paragraph(key+": "+val, size, false)
}

func (b *pdfBuilder) section(sec Section) {
	if sec.Heading != "" {
		b.heading(sec.Level+1, sec.Heading)
	}
	for _, p := range sec.Paragraphs {
		b.paragraph(p, 10, false)
		b.gap()
	}
	for _, kv := range sec.KV {
		b.kv(kv.Key, kv.Value, 10)
	}
	if len(sec.KV) > 0 {
		b.gap()
	}
	if sec.Table != nil {
		b.table(*sec.Table)
	}
	for _, f := range sec.Findings {
		b.finding(f)
	}
}

func (b *pdfBuilder) finding(f FindingBlock) {
	b.heading(4, f.Title)
	domain := f.Domain
	if f.Service != "" {
		domain += " (" + f.Service + ")"
	}
	b.kv("Domain", domain, 9)
	b.kv("Remediation", f.RemediationLabel, 9)
	b.gap()
	if f.Description != "" {
		b.paragraph("What this means: "+f.Description, 10, false)
		b.gap()
	}
	switch {
	case f.HowToFix != "":
		b.paragraph("How to fix it: "+f.HowToFix, 10, false)
		b.gap()
	case f.WhyNoFix != "":
		b.paragraph("Why hostveil won't do this for you: "+f.WhyNoFix, 10, false)
		b.gap()
	}
	if f.FixBenefit != "" {
		b.paragraph("Benefit: "+f.FixBenefit, 10, false)
		b.gap()
	}
	if f.FixSideEffect != "" {
		b.paragraph("Side effect: "+f.FixSideEffect, 10, false)
		b.gap()
	}
	if len(f.Evidence) > 0 {
		b.table(Table{Headers: []string{"Key", "Value"}, Rows: kvRows(f.Evidence)})
	}
	b.gap()
}

// table draws a fixed-column grid as plain aligned text, one line per row —
// no ruled borders, which a monospace-style column layout does not need to
// stay readable. Cells are truncated to fit their column rather than
// wrapped, so a table stays exactly one line per row.
func (b *pdfBuilder) table(t Table) {
	if len(t.Headers) == 0 {
		return
	}
	colW := pdfContentW / float64(len(t.Headers))
	size := 9.0
	b.row(t.Headers, colW, size, true)
	for _, r := range t.Rows {
		b.row(r, colW, size, false)
	}
	b.gap()
}

func (b *pdfBuilder) row(cells []string, colW, size float64, bold bool) {
	lead := b.leading(size)
	b.ensure(lead)
	font := "F1"
	if bold {
		font = "F2"
	}
	for i, c := range cells {
		x := pdfMargin + float64(i)*colW
		fmt.Fprintf(&b.cur, "BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n",
			font, size, x, b.y, pdfEscape(pdfFitColumn(c, bold, size, colW-6)))
	}
	b.y -= lead
}

func (b *pdfBuilder) write() ([]byte, error) {
	b.newPage() // flush the in-progress page
	return renderPDF(b.pages), nil
}

// ── text measurement and wrapping ──────────────────────────────────────

// helveticaWidths is the Adobe standard Helvetica AFM advance width (in
// 1/1000 em) for printable ASCII 32-126. Used, with a fixed approximation,
// for Helvetica-Bold too: bold runs slightly wider in practice, and callers
// leave enough right-margin headroom that the difference never overflows a
// line in the content this report produces.
var helveticaWidths = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

func charWidth(r rune) int {
	if r < 32 || r > 126 {
		return 556
	}
	return helveticaWidths[r-32]
}

func textWidthPDF(s string, size float64) float64 {
	total := 0
	for _, r := range s {
		total += charWidth(r)
	}
	return float64(total) * size / 1000
}

// wrapPDF greedily wraps text into lines that fit maxWidth at the given
// size, splitting only on spaces. bold is accepted for signature symmetry
// with the shared width table; see helveticaWidths.
func wrapPDF(text string, _ bool, size, maxWidth float64) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		candidate := line + " " + w
		if textWidthPDF(candidate, size) > maxWidth {
			lines = append(lines, line)
			line = w
			continue
		}
		line = candidate
	}
	lines = append(lines, line)
	return lines
}

// pdfFitColumn truncates s with an ellipsis so it fits width points at
// size — table cells stay one line each.
func pdfFitColumn(s string, _ bool, size, width float64) string {
	if textWidthPDF(s, size) <= width {
		return s
	}
	const ellipsis = "…"
	for len([]rune(s)) > 0 {
		s = s[:len(s)-1]
		if textWidthPDF(s+ellipsis, size) <= width {
			return s + ellipsis
		}
	}
	return ellipsis
}

// pdfEscape encodes s as a PDF literal string: backslash/parens escaped,
// and anything outside Latin-1 (which the base-14 WinAnsi encoding cannot
// represent) replaced with '?' rather than corrupting the byte stream with
// raw UTF-8.
func pdfEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\\' || r == '(' || r == ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r < 256:
			//nolint:gosec // G115: the case guard (r < 256) is exactly the bounds check the rule wants
			b.WriteByte(byte(r))
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}
