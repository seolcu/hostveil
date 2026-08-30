package report

import (
	"strings"
	"testing"
)

func TestExportJSONMatchesClirender(t *testing.T) {
	r := sampleReport()
	data, f, err := Export(r, "v-test", "json")
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != "json" {
		t.Errorf("resolved format = %q, want json", f.ID)
	}
	want, err := jsonBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Error("Export(\"json\") diverges from clirender.JSON")
	}
}

func TestExportSARIFMatchesClirender(t *testing.T) {
	r := sampleReport()
	data, _, err := Export(r, "v-test", "sarif")
	if err != nil {
		t.Fatal(err)
	}
	want, err := sarifBytes(r, "v-test")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Error("Export(\"sarif\") diverges from clirender.SARIF")
	}
}

func TestExportEveryFormatProducesNonEmptyOutput(t *testing.T) {
	r := sampleReport()
	for _, f := range All() {
		data, got, err := Export(r, "v-test", f.ID)
		if err != nil {
			t.Errorf("Export(%q) failed: %v", f.ID, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("Export(%q) returned no bytes", f.ID)
		}
		if got.ID != f.ID {
			t.Errorf("Export(%q) resolved format %q", f.ID, got.ID)
		}
	}
}

func TestExportUnknownFormatErrorsAndNamesTheChoices(t *testing.T) {
	_, _, err := Export(sampleReport(), "v-test", "yaml")
	if err == nil {
		t.Fatal("Export(\"yaml\") should fail")
	}
	if !strings.Contains(err.Error(), "markdown") {
		t.Errorf("error %q should name the valid choices", err.Error())
	}
}
