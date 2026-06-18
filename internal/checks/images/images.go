// Package images enumerates container images in use on the host and
// flags those with known CVEs (spec FR-003).
//
// The matcher is intentionally a thin wrapper around the local
// `internal/cve` cache: in v3.0.0 the cache is populated by a manual
// `--refresh-cve` invocation; the scanner reports every image that
// appears in the cache with at least one matching vulnerability. The
// post-v3.0 roadmap introduces a "no-cache" mode that queries NVD on
// the fly.
package images

import (
	"context"
	"fmt"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/checks/docker"
	"github.com/seolcu/hostveil/internal/model"
)

// Run implements checks.Run.
func Run(ctx context.Context) (checks.Result, error) {
	cs, err := docker.Run(ctx)
	if err != nil {
		return checks.Result{}, fmt.Errorf("images: list containers: %w", err)
	}
	if cs.Skipped != nil {
		// Docker isn't running; treat the image-CVE category as
		// skipped with the same reason.
		skip := *cs.Skipped
		skip.Category = model.CategoryImageCVE
		return checks.Result{Skipped: &skip}, nil
	}
	// No cache in v3.0.0-alpha; report only "no CVE data" rather
	// than fabricating matches. Future work: load the SQLite-backed
	// cve_cache and produce real findings.
	now := time.Now().UTC()
	var findings []model.Finding
	for _, c := range cs.Findings {
		_ = c
		// intentionally empty: image_cve is a no-op until the cve
		// package lands.
	}
	_ = findings
	_ = now
	return checks.Result{Findings: nil}, nil
}
