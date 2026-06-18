// Package report owns the rendering of a scan run to stdout / file
// (text) and to the JSON contract (machine-readable). The redaction
// list in redact.go is the single source of truth for what must never
// appear in either output (PEM private keys, named credential fields,
// URL credentials, AWS access keys).
package report

import (
	"github.com/seolcu/hostveil/internal/model"
)

// Run is the top-level shape of the JSON report, matching
// contracts/report.md. Text and JSON renderers read the same Run
// value; the text renderer never invents fields the JSON does not
// have.
type Run struct {
	SchemaVersion     string         `json:"schema_version"`
	HostveilVersion   string         `json:"hostveil_version"`
	HostveilCommit    string         `json:"hostveil_commit"`
	HostveilBuiltAt   string         `json:"hostveil_built_at"`
	ScanRun           model.ScanRun  `json:"scan_run"`
	Host              model.Host     `json:"host"`
	Findings          []model.Finding `json:"findings"`
}
