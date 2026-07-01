# trivy

Adapter for the [Trivy](https://github.com/aquasecurity/trivy)
scanner. hostveil shells out to `trivy image`, once per unique
image referenced by a compose project, and translates the JSON
output into `domain.Finding` values.

**Image CVEs only — no config/IaC scanning.** An earlier version
ran `trivy config` against each compose file for misconfiguration
findings, but that scan never actually produced compose findings
in practice, so it was replaced by hostveil's own
`internal/composeaudit` package (commit `c496c34`). This package's
only job now is CVE detection in container images.

## Files

- **`trivy.go`** — `ScanAll` (discovers compose projects via
  `composeaudit.DiscoverProjects`, then scans each one),
  `scanProject`, `extractImages`, `runImage` (the actual
  `trivy image` invocation), the JSON decoders, and the
  per-finding constructor.
- **`trivy_test.go`** — tests for the image extractor
  (`TestExtractImages*`), the JSON decoder
  (`TestDecodeTrivyJSON*`), and the severity mapper
  (`TestParseSeverity`).

## What we call

```bash
trivy image --format json --quiet --severity <lvl> --timeout 5m <image>  # once per unique image
```

`extractImages` walks every service in a compose file's `image:`
field, dedupes them, and `ScanAll` runs one `trivy image` per
unique image across all discovered compose projects.

## CVE classification

CVE findings are produced in two stages:

1. The fix registry (`internal/fix/images.go`) classifies them
   `Auto` when a `FixedVersion` is present.
2. `overrideCVEClassifications` in `internal/scan/scan.go`
   demotes any remaining `trivy.cve-*` findings without a
   `FixedVersion` to `Manual` (no upstream patch yet).

## Tests

```bash
go test ./internal/trivy/...
```

`trivy_test.go` runs without an actual Trivy binary — the tests
use canned JSON output. Integration with Trivy is covered by the
end-to-end smoke flow (`./hostveil` on a host that has Trivy
installed).
