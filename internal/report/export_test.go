package report

import (
	"strings"
	"testing"
)

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
