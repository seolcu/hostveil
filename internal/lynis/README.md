# lynis

Adapter for the [Lynis](https://github.com/CISOfy/lynis) host
hardening auditor. hostveil shells out to `lynis audit system`,
then translates the `report.dat` output into `domain.Finding`
values.

## Files

- **`lynis.go`**  `Scan` (the entry point), `runLynis` (the shell
  call), `parseReportFile` (the line-by-line parser), and the
  per-line parsers `parseEntry`, `parseManualEntry`, and
  `parseExceptionEntry`.
- **`lynis_test.go`**  parser tests. Canned `report.dat`
  snippets.

## What we call

```bash
lynis audit system --quiet --report-file <tmp>
```

Lynis writes a `report.dat` file (a line-oriented text file with
`key=value` pairs). hostveil writes the report to a temp file
(`hostveil-lynis-*.dat`) and reads it back; the temp file is
removed on exit.

## Parsing rules

The parser matches four kinds of lines:

| Line prefix | Severity | Remediation |
|-------------|----------|-------------|
| `warning[]=` | High | Auto / Review (set by the fix registry) |
| `suggestion[]=` | Medium | Auto / Review (set by the fix registry) |
| `manual_event[]=` | Medium | Manual |
| `exception_event[]=` | Low | Unavailable |

Each line is split on `|` into `(ID, Description, Remediation,
Extra)`. The ID is prefixed with `lynis.` to form the canonical
finding ID (e.g. `lynis.AUTH-9286`).

The `Extra` column becomes a `Finding.Evidence["extra"]` entry.
For some specific IDs (`FILE-6405`, `ACCT-9626`, `FIRE-4513`)
the parser extracts more specific evidence fields. See
`parseEntry_Evidence_*` in `lynis_test.go` for the expectations.

## How fixes are linked

`internal/fix/system.go` registers one `fix.Fix` per Lynis test
ID. The fix ID and the finding ID match (with the `lynis.`
prefix). `internal/fix/system_validate_test.go` asserts that every
registered ID is one that `lynis.Scan` actually emits  so a
finding without a registered fix is fine, but a registered fix
for an ID the parser never produces is a bug.

## Tests

```bash
go test ./internal/lynis/...
go test -race ./internal/lynis/...
```
