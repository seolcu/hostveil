# trivy

Adapter for the [Trivy](https://github.com/aquasecurity/trivy)
scanner. hostveil shells out to `trivy config` and `trivy image`,
then translates the JSON output into `domain.Finding` values.

## Files

- **`trivy.go`** — `ScanAll`, `scanConfig`, `scanImage`, the JSON
  decoders, and the per-finding constructor. The `extractImages`
  helper walks a Trivy report to collect the unique image names
  that need a CVE scan.
- **`trivy_test.go`** — tests for the image extractor, the JSON
  decoder, and the severity mapper.

## What we call

```bash
trivy config --format json --quiet <compose-path>      # one per project
trivy image --format json --quiet --severity <lvl> ...  # one per image
```

The `trivy config` output is for IaC / compose misconfigurations.
hostveil runs it for every `docker compose ls` project and merges
the findings into the snapshot.

The `trivy image` output is for CVE findings. hostveil extracts
the unique image names from the Trivy report and runs `trivy image`
once per image.

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
