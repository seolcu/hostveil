package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
)

// docx renders d as a minimal but valid Office Open XML Word document — a
// zip of a handful of XML parts, hand-written rather than pulled from a
// third-party library. The content this report needs (headings, paragraphs,
// bold runs, simple tables) is small enough that owning it costs less than
// vetting a dependency for a tool that ships SBOMs and provenance
// attestations, and it is the same call this codebase already made for
// SARIF.
//
// Every paragraph/heading style referenced (Heading1, Heading2, Normal) is
// one of Word's built-in styles, so no styles.xml customization is needed —
// every reader (Word, LibreOffice, Word Online) already has them.
func docx(d Doc) ([]byte, error) {
	var body bytes.Buffer
	body.WriteString(docxHeading(1, d.Title))
	sub := "Generated " + d.Generated.Format("2006-01-02 15:04 MST") + " by hostveil " + d.Version
	if d.Hostname != "" {
		sub += " on " + d.Hostname
	}
	body.WriteString(docxParagraph(sub))

	for _, sec := range d.Sections {
		writeDocxSection(&body, sec)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := map[string]string{
		"[Content_Types].xml":          docxContentTypes,
		"_rels/.rels":                  docxRels,
		"word/_rels/document.xml.rels": docxDocumentRels,
		"word/document.xml":            docxDocumentXML(body.String()),
		"word/styles.xml":              docxStyles,
	}
	for name, content := range parts {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeDocxSection(body *bytes.Buffer, sec Section) {
	if sec.Heading != "" {
		body.WriteString(docxHeading(sec.Level+1, sec.Heading))
	}
	for _, p := range sec.Paragraphs {
		body.WriteString(docxParagraph(p))
	}
	for _, kv := range sec.KV {
		body.WriteString(docxParagraphBold(kv.Key, kv.Value))
	}
	if sec.Table != nil {
		body.WriteString(docxTable(*sec.Table))
	}
	for _, f := range sec.Findings {
		writeDocxFinding(body, f)
	}
}

func writeDocxFinding(body *bytes.Buffer, f FindingBlock) {
	body.WriteString(docxHeading(3, f.Title))
	domain := f.Domain
	if f.Service != "" {
		domain += " (" + f.Service + ")"
	}
	body.WriteString(docxParagraphBold("Domain", domain))
	body.WriteString(docxParagraphBold("Remediation", f.RemediationLabel))
	if f.Description != "" {
		body.WriteString(docxParagraphBold("What this means", f.Description))
	}
	switch {
	case f.HowToFix != "":
		body.WriteString(docxParagraphBold("How to fix it", f.HowToFix))
	case f.WhyNoFix != "":
		body.WriteString(docxParagraphBold("Why hostveil won't do this for you", f.WhyNoFix))
	}
	if f.FixBenefit != "" {
		body.WriteString(docxParagraphBold("Benefit", f.FixBenefit))
	}
	if f.FixSideEffect != "" {
		body.WriteString(docxParagraphBold("Side effect", f.FixSideEffect))
	}
	if len(f.Evidence) > 0 {
		body.WriteString(docxTable(Table{Headers: []string{"Key", "Value"}, Rows: kvRows(f.Evidence)}))
	}
}

func docxEscape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func docxHeading(level int, text string) string {
	style := fmt.Sprintf("Heading%d", level)
	if level > 4 {
		style = "Heading4"
	}
	return fmt.Sprintf(`<w:p><w:pPr><w:pStyle w:val="%s"/></w:pPr><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		style, docxEscape(text))
}

func docxParagraph(text string) string {
	return fmt.Sprintf(`<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, docxEscape(text))
}

func docxParagraphBold(label, text string) string {
	return fmt.Sprintf(`<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s: </w:t></w:r>`+
		`<w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, docxEscape(label), docxEscape(text))
}

// docxTblBorders draws a plain single-line grid inline, rather than via a
// named table style, so the table renders consistently without depending on
// styles.xml defining a "TableGrid" style a reader might not recognize.
const docxTblBorders = `<w:tblBorders>` +
	`<w:top w:val="single" w:sz="4" w:color="auto"/>` +
	`<w:left w:val="single" w:sz="4" w:color="auto"/>` +
	`<w:bottom w:val="single" w:sz="4" w:color="auto"/>` +
	`<w:right w:val="single" w:sz="4" w:color="auto"/>` +
	`<w:insideH w:val="single" w:sz="4" w:color="auto"/>` +
	`<w:insideV w:val="single" w:sz="4" w:color="auto"/>` +
	`</w:tblBorders>`

func docxTable(t Table) string {
	var b bytes.Buffer
	b.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/>` + docxTblBorders + `</w:tblPr>`)
	writeDocxRow(&b, t.Headers, true)
	for _, row := range t.Rows {
		writeDocxRow(&b, row, false)
	}
	b.WriteString(`</w:tbl>`)
	// A table must not be the last thing in the document body per the OOXML
	// schema — Word repairs the file rather than opening it as-is otherwise.
	b.WriteString(`<w:p/>`)
	return b.String()
}

func writeDocxRow(b *bytes.Buffer, cells []string, bold bool) {
	b.WriteString(`<w:tr>`)
	for _, c := range cells {
		b.WriteString(`<w:tc><w:p>`)
		if bold {
			b.WriteString(`<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">` + docxEscape(c) + `</w:t></w:r>`)
		} else {
			b.WriteString(`<w:r><w:t xml:space="preserve">` + docxEscape(c) + `</w:t></w:r>`)
		}
		b.WriteString(`</w:p></w:tc>`)
	}
	b.WriteString(`</w:tr>`)
}

func docxDocumentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body>` + body + `<w:sectPr/></w:body></w:document>`
}

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`</Types>`

const docxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

const docxDocumentRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>` +
	`</Relationships>`

// docxStyles defines Normal and four heading levels so w:pStyle references
// in the body actually render as headings rather than falling back to plain
// text — a reader is not required to invent formatting for a style ID it
// cannot find defined anywhere in the package.
const docxStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
	`<w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/></w:rPr></w:rPrDefault></w:docDefaults>` +
	`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>` +
	`<w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>` +
	`<w:pPr><w:spacing w:before="200" w:after="100"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>` +
	`<w:pPr><w:spacing w:before="160" w:after="80"/></w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>` +
	`<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/>` +
	`<w:pPr><w:spacing w:before="120" w:after="60"/></w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>` +
	`</w:styles>`
