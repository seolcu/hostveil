package report

import (
	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/model"
)

// jsonBytes reuses clirender.JSON verbatim, so `hostveil export --format
// json` and `hostveil scan --json` are byte-identical.
func jsonBytes(r model.Report) ([]byte, error) {
	s, err := clirender.JSON(r)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
