package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestDOCXIsAValidZipWithParsableDocumentXML(t *testing.T) {
	data, _, err := Export(sampleReport(), "v-test", "docx")
	if err != nil {
		t.Fatal(err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("docx is not a valid zip: %v", err)
	}

	want := map[string]bool{
		"[Content_Types].xml":          false,
		"_rels/.rels":                  false,
		"word/document.xml":            false,
		"word/_rels/document.xml.rels": false,
		"word/styles.xml":              false,
	}
	var docXML []byte
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			docXML, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("docx is missing required part %q", name)
		}
	}

	var doc struct {
		XMLName xml.Name `xml:"document"`
		Body    struct {
			P []struct {
				Inner string `xml:",innerxml"`
			} `xml:"p"`
			Tbl []struct {
				Inner string `xml:",innerxml"`
			} `xml:"tbl"`
		} `xml:"body"`
	}
	if err := xml.Unmarshal(docXML, &doc); err != nil {
		t.Fatalf("word/document.xml does not parse as XML: %v", err)
	}
	if len(doc.Body.P) == 0 {
		t.Error("document.xml has no paragraphs")
	}
	if len(doc.Body.Tbl) == 0 {
		t.Error("document.xml has no tables (expected at least the score-by-domain table)")
	}

	if !strings.Contains(string(docXML), "SSH permits root login") {
		t.Error("a finding's title does not appear in document.xml")
	}
}
