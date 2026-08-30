package report

import (
	"github.com/seolcu/hostveil/internal/clirender"
	"github.com/seolcu/hostveil/internal/model"
)

// sarifBytes reuses clirender.SARIF verbatim, so `hostveil export --format
// sarif` and `hostveil scan --sarif` are byte-identical.
func sarifBytes(r model.Report, version string) ([]byte, error) {
	s, err := clirender.SARIF(r, version)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}
