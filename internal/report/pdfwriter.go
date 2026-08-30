package report

import (
	"bytes"
	"fmt"
)

// renderPDF serializes a finished set of per-page content streams into a
// minimal, valid PDF 1.4 file: one Catalog, one Pages tree, two base-14
// font resources shared by every page, and one Page + Contents object pair
// per page, followed by a byte-accurate xref table and trailer.
func renderPDF(pages [][]byte) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	offsets := []int{0} // index 0 is the free-list head; real objects start at 1

	writeObj := func(n int, body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
	}

	const (
		catalogObj = 1
		pagesObj   = 2
		fontRegObj = 3
		fontBldObj = 4
		firstPage  = 5
	)

	pageObjNums := make([]int, len(pages))
	for i := range pages {
		pageObjNums[i] = firstPage + i*2
	}

	kids := ""
	for _, n := range pageObjNums {
		kids += fmt.Sprintf("%d 0 R ", n)
	}

	writeObj(catalogObj, fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObj))
	writeObj(pagesObj, fmt.Sprintf("<< /Type /Pages /Kids [ %s] /Count %d >>", kids, len(pages)))
	writeObj(fontRegObj, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	writeObj(fontBldObj, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

	for i, content := range pages {
		pageObj := pageObjNums[i]
		contentObj := pageObj + 1
		writeObj(pageObj, fmt.Sprintf(
			"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.0f %.0f] "+
				"/Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>",
			pagesObj, pdfPageW, pdfPageH, fontRegObj, fontBldObj, contentObj))
		writeObj(contentObj, fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))
	}

	xrefStart := out.Len()
	totalObjs := len(offsets) // includes the object-0 placeholder
	fmt.Fprintf(&out, "xref\n0 %d\n", totalObjs)
	out.WriteString("0000000000 65535 f \n")
	for _, off := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}

	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF",
		totalObjs, catalogObj, xrefStart)

	return out.Bytes()
}
