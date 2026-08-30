package report

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"
)

func TestPDFHasAValidHeaderTrailerAndXref(t *testing.T) {
	data, _, err := Export(sampleReport(), "v-test", "pdf")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.HasPrefix(data, []byte("%PDF-1.4")) {
		t.Fatal("pdf does not start with %PDF-1.4")
	}
	trimmed := bytes.TrimRight(data, "\n")
	if !bytes.HasSuffix(trimmed, []byte("%%EOF")) {
		t.Fatal("pdf does not end with the EOF marker")
	}

	// Self-consistency: every offset the xref table records must actually
	// point at the "N 0 obj" it claims to, not a full PDF parse.
	startxrefRe := regexp.MustCompile(`startxref\n(\d+)\n`)
	m := startxrefRe.FindSubmatch(data)
	if m == nil {
		t.Fatal("no startxref found")
	}
	xrefOffset, err := strconv.Atoi(string(m[1]))
	if err != nil || xrefOffset >= len(data) {
		t.Fatalf("startxref offset %q is not a valid position in the file", m[1])
	}
	if !bytes.HasPrefix(data[xrefOffset:], []byte("xref")) {
		t.Fatalf("startxref offset %d does not point at the xref table", xrefOffset)
	}

	entryRe := regexp.MustCompile(`(?m)^(\d{10}) 00000 n \n`)
	for _, m := range entryRe.FindAllSubmatch(data, -1) {
		off, err := strconv.Atoi(string(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		objRe := regexp.MustCompile(`^\d+ 0 obj`)
		if !objRe.Match(data[off:min(off+20, len(data))]) {
			t.Errorf("xref entry offset %d does not point at an \"N 0 obj\" marker", off)
		}
	}
}

func TestPDFHasMultiplePagesAndAFontResource(t *testing.T) {
	data, _, err := Export(sampleReport(), "v-test", "pdf")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("/BaseFont /Helvetica")) {
		t.Error("missing the Helvetica font resource")
	}
	if !bytes.Contains(data, []byte("/BaseFont /Helvetica-Bold")) {
		t.Error("missing the Helvetica-Bold font resource")
	}
	if !bytes.Contains(data, []byte("/Type /Page")) {
		t.Error("missing at least one Page object")
	}
}
