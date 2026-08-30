package core

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestEngineExportFormatsMatchesReportAll(t *testing.T) {
	formats := ExportFormats()
	if len(formats) != 5 {
		t.Fatalf("ExportFormats() returned %d formats, want 5 (json, sarif, markdown, docx, pdf)", len(formats))
	}
	for _, f := range formats {
		if f.ID == "" || f.Label == "" || f.Ext == "" {
			t.Errorf("format %+v has an empty field", f)
		}
	}
}

func TestEngineExportEveryFormat(t *testing.T) {
	e := &Engine{version: "v-test"}
	r := model.Report{Findings: []model.Finding{
		model.NewFinding("ssh.rootlogin", "Root login allowed", model.SeverityHigh,
			model.SourceSSH, model.RemediationReview),
	}}
	for _, f := range ExportFormats() {
		data, filename, contentType, err := e.Export(r, f.ID)
		if err != nil {
			t.Errorf("Export(%q) failed: %v", f.ID, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("Export(%q) returned no bytes", f.ID)
		}
		if !strings.HasSuffix(filename, "."+f.Ext) {
			t.Errorf("Export(%q) filename %q does not end in .%s", f.ID, filename, f.Ext)
		}
		if contentType == "" {
			t.Errorf("Export(%q) returned no content type", f.ID)
		}
	}
}

func TestEngineExportUnknownFormatErrors(t *testing.T) {
	e := &Engine{version: "v-test"}
	_, _, _, err := e.Export(model.Report{}, "yaml")
	if err == nil {
		t.Fatal("Export(\"yaml\") should fail")
	}
}
