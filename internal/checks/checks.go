// Package checks contains the per-category scanners. Each scanner is a
// Go package under internal/checks/<category>/ and exposes a single
// Run(ctx) ([]model.Finding, error) function. The orchestrator
// (internal/scan) calls each scanner in turn, with elevation handled
// by internal/platform/privilege.
package checks

import (
	"context"

	"github.com/seolcu/hostveil/internal/model"
)

// Result is what a scanner returns. Skipped is set when the scanner
// could not run (e.g. missing prerequisite, elevation denied); the
// orchestrator records a CategorySkip row and continues.
type Result struct {
	Findings []model.Finding
	Skipped  *model.CategorySkip
}

// Run is the contract every scanner satisfies. The host is implicit
// (the local host); the scanner may read it directly. Context carries
// the scan_run_id and the privilege helper.
type Run func(ctx context.Context) (Result, error)
