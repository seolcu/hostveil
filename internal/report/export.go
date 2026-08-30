package report

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// Export renders r in the named format, returning the bytes and the
// resolved Format (whose Ext/ContentType/Label a caller needs to name the
// output). version is the hostveil build version, embedded in the SARIF
// tool driver and the Markdown/DOCX/PDF header.
func Export(r model.Report, version, formatID string) ([]byte, Format, error) {
	f, ok := Parse(formatID)
	if !ok {
		return nil, Format{}, fmt.Errorf("unknown export format %q (choices: %s)", formatID, formatChoices())
	}

	switch f.ID {
	case "json":
		data, err := jsonBytes(r)
		return data, f, err
	case "sarif":
		data, err := sarifBytes(r, version)
		return data, f, err
	default:
		d := buildDoc(r, version)
		var data []byte
		var err error
		switch f.ID {
		case "markdown":
			data, err = markdown(d)
		case "docx":
			data, err = docx(d)
		case "pdf":
			data, err = pdf(d)
		}
		return data, f, err
	}
}

func formatChoices() string {
	s := ""
	for i, f := range formats {
		if i > 0 {
			s += ", "
		}
		s += f.ID
	}
	return s
}
