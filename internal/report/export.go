package report

import (
	"fmt"

	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/model"
)

// Export renders r in the named format, returning the bytes and the
// resolved Format (whose Ext/ContentType/Label a caller needs to name the
// output). version is the Hostveil build version, embedded in the SARIF
// tool driver and the Markdown header.
func Export(r model.Report, version, formatID string) ([]byte, Format, error) {
	f, ok := Parse(formatID)
	if !ok {
		return nil, Format{}, fmt.Errorf("unknown export format %q (choices: %s)", formatID, formatChoices())
	}

	var out string
	var err error
	switch f.ID {
	case "json":
		// The same renderer as `scan --json` and `scan --sarif`, so the two
		// routes produce byte-identical output.
		out, err = clirender.JSON(r)
	case "sarif":
		out, err = clirender.SARIF(r, version)
	case "markdown":
		var data []byte
		data, err = markdown(buildDoc(r, version))
		return data, f, err
	}
	return []byte(out), f, err
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
