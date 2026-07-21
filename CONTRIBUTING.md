# Contributing

Thanks for looking. hostveil is a single Go binary that scans a Linux server,
scores it, and fixes what it safely can.

## Getting set up

```bash
git clone https://github.com/seolcu/hostveil
cd hostveil
go build ./cmd/hostveil
go test ./...
```

Go 1.26. No other tooling is required to build or test.

## Running it for real

The binary compiles and tests everywhere, but only *does* anything on Linux
with docker, ssh, and a firewall present. **Do not run it against your own
machine** — it applies changes to system files. Use the Vagrant demo VM, which
rsyncs your working tree in and rebuilds:

```bash
cd demo && ./run.sh up      # then: ./run.sh scan | web | shell | reset | halt
```

The VM is deliberately misconfigured, so it has something to find.
`./run.sh reset` puts it back.

## Before you open a pull request

Run the same gate CI does:

```bash
go build ./... && go vet ./... && gofmt -l . && go mod tidy && go test -race ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run ./cmd/sitegen && git diff --exit-code site/
```

`go run` works for the linters without installing anything.

**Pull request titles matter.** Merges are squashed and the title becomes the
commit subject, which drives the version bump and the changelog. It must be
conventional — `fix(check): ...`, `feat(ui): ...` — and the scope comes from a
closed allowlist enforced by CI. Put the component in the *scope*, never the
type. `AGENTS.md` has the full list and the reasoning.

## What makes a change likely to be merged

hostveil's only real claim is that **its score is honest**. Most of the
project's rules exist to protect that, and they are documented as invariants in
`AGENTS.md` — worth reading before a first change. The two that come up most:

- **"I couldn't look" must never score the same as "nothing there."** A checker
  that cannot examine its ground reports `Available() = false` (skipped, axis
  excluded) or returns a `check.PartialError` (degraded, axis flagged). It must
  never return no findings and let that be read as clean.
- **A fix is Auto only if it is safe to apply unattended.** That means
  reversible, recoverable even if wrong (nothing that can cut off the
  operator's own SSH access), and unambiguous. Anything else is Review, or
  Manual. The full standard is the doc comment on `fix.Default()` in
  `internal/fix/register.go`.

New detection rules are welcome. A rule that fires on a correctly configured
host is worse than no rule at all, so please include the case that must *not*
trigger it alongside the case that must.

## Reporting things

- **A finding hostveil misses, or reports wrongly** — open an issue. Include
  the relevant config and what you expected. These are the most useful reports
  the project gets.
- **A security vulnerability in hostveil itself** — see `SECURITY.md`; report
  it privately rather than in an issue.

## License

Contributions are made under the GPL-3.0, the same license as the project.
