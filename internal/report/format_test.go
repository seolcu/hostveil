package report

import "testing"

func TestEveryFormatParsesBackByItsOwnID(t *testing.T) {
	for _, f := range All() {
		got, ok := Parse(f.ID)
		if !ok {
			t.Errorf("Parse(%q) failed to resolve a format All() lists", f.ID)
			continue
		}
		if got != f {
			t.Errorf("Parse(%q) = %+v, want %+v", f.ID, got, f)
		}
		if f.Ext == "" || f.ContentType == "" || f.Label == "" {
			t.Errorf("format %q is missing Ext/ContentType/Label: %+v", f.ID, f)
		}
	}
}

func TestParseRejectsUnknownFormat(t *testing.T) {
	if _, ok := Parse("yaml"); ok {
		t.Error("Parse(\"yaml\") should fail; yaml is not a supported export format")
	}
}
