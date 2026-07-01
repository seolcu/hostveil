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

The parser matches four line prefixes, and **each has a different
field format** — they are not variations on one shared layout:

| Line prefix | Format | Finding ID | Severity | Remediation |
|---|---|---|---|---|
| `warning[]=` | `TEST_ID\|Description\|Remediation\|Extra` (pipe-split, at least 2 fields required; a 5th+ field, if present, is silently ignored) | `lynis.TEST_ID` | High | Auto / Review (set by the fix registry) |
| `suggestion[]=` | same as `warning[]=` | `lynis.TEST_ID` | Medium | Auto / Review (set by the fix registry) |
| `manual_event[]=` | free text, no delimiter | `lynis.manual.<8-hex-char sha256 of the text>` | Medium | Manual |
| `exception_event[]=` | `TEST_ID\|Message` (pipe-split, at least 2 fields — only the first two are read, extras ignored; no Remediation/Extra field) | `lynis.exception.TEST_ID` (or bare `lynis.exception` if `TEST_ID` is empty) | Low | Unavailable |

For `warning[]=`/`suggestion[]=`, the 3rd field (if present) becomes
`Finding.HowToFix` and the 4th field (if present and non-empty)
becomes `Finding.Evidence["extra"]`. There is **no per-test-ID
special-casing** — every warning/suggestion, regardless of which
Lynis test produced it, gets the exact same generic
`Evidence["extra"]` treatment. `TestParseEntry_Evidence_FILE6405`,
`_ACCT9626`, and `_FIRE4513` in `lynis_test.go` exist specifically
to assert this — each one checks that no ID-specific `Evidence` key
(`path`, `user`, `port`) is added, only the generic `extra`.
`manual_event[]=` and `exception_event[]=` findings have no
`Evidence` at all.

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
