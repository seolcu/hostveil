# Quickstart: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](./spec.md)
**Plan**: [plan.md](./plan.md)
**Data Model**: [data-model.md](./data-model.md)
**Research**: [research.md](./research.md)

This document is a runnable validation guide for v3.0.0. It walks
through installing the binary, running a full scan, reading the
report, applying one fix, rolling it back, and confirming the
roll-back matches the pre-fix state byte-for-byte. Every step in
this document is exercised by `tests/integration/`; if a step here
fails, the integration suite fails too.

If you only want to see the product work end to end, follow the
**"Five-minute tour"** below. If you are validating the v3.0.0
release candidate, follow the **"Release validation"** sequence.

---

## Prerequisites

- A Linux host. v3.0.0 supports `linux/amd64` and `linux/arm64`
  out of the box; `linux/386` and `linux/armv7` are best-effort
  with no CI gate.
- A user account that can read system configuration files
  (`/etc/ssh/sshd_config`, `/etc/docker/daemon.json`, etc.) and
  is in the `sudo` or `wheel` group, so the program can elevate
  for the hardening checks.
- Docker installed and running, if you want the Docker and
  image-CVE categories to produce findings. Without Docker,
  those categories are reported as `not_applicable` and the rest
  of the scan still works.
- A terminal that can prompt for the sudo password. In a headless
  context (no TTY) the elevated categories are skipped with
  `headless_no_tty`; the rest of the scan still runs.
- Approximately 50 MB of free disk under `~/.local/share/hostveil/`
  for the database, the report, and the CVE cache.

The quickstart does not require the v2.5.2 codebase to be
present. v3 is a full rewrite from a clean checkout.

---

## Install

Pick one of the following. All three produce a single static
binary at `/usr/local/bin/hostveil` (or wherever you choose).

### From a release tarball

```bash
# Replace URLs with the actual v3.0.0 release.
curl -L -o /tmp/hostveil.tgz \
  https://github.com/<owner>/hostveil/releases/download/v3.0.0/hostveil_3.0.0_linux_amd64.tar.gz
tar -xzf /tmp/hostveil.tgz -C /tmp
sudo install -m 0755 /tmp/hostveil /usr/local/bin/hostveil
hostveil version
```

Expected: prints `hostveil v3.0.0 (commit <sha>, built <RFC3339>)`.

### From source

```bash
git clone https://github.com/<owner>/hostveil
cd hostveil
git checkout v3.0.0
./scripts/build.sh
sudo install -m 0755 dist/hostveil /usr/local/bin/hostveil
hostveil version
```

`scripts/build.sh` produces a reproducible build with `-trimpath`
and embeds the version, commit, and build date.

### From a package

```bash
# Debian / Ubuntu
sudo dpkg -i hostveil_3.0.0_amd64.deb
# RHEL / Fedora
sudo dnf install ./hostveil-3.0.0-1.x86_64.rpm
```

After install, verify:

```bash
hostveil version
```

---

## Five-minute tour

This is the shortest path to a useful result. Run each command and
compare its output to the "Expected" line.

### 1. Run a scan

```bash
hostveil scan
```

Expected:
- The program writes progress lines to stderr and the report to
  stdout.
- A sudo / pkexec prompt appears at most once, asking for the
  categories that need elevation. Enter your password.
- The program exits with code `0` (no high or critical findings)
  or `1` (at least one). Note the exit code with
  `echo $?`.
- A report file is written to
  `~/.local/share/hostveil/reports/hostveil-YYYYMMDD-HHMMSS.txt`.
  The path is printed in the report's header.

### 2. Read the report

```bash
ls -1 ~/.local/share/hostveil/reports/ | tail -n 1
less $(ls -1t ~/.local/share/hostveil/reports/ | head -n 1)
```

Expected: the file has the five sections described in
`contracts/report.md` (Header, Summary, Findings, Skipped
categories, Footer).

### 3. Get the JSON form

```bash
hostveil scan --format=json --no-report-file | jq '.scan_run.finding_count_by_severity'
```

Expected: an object with the four severity keys, e.g.
`{ "critical": 0, "high": 1, "medium": 3, "low": 0 }`.

### 4. Explain a finding

```bash
hostveil explain <finding-id>
```

Replace `<finding-id>` with the `id` of any finding in the most
recent report. To find ids without scrolling:

```bash
hostveil scan --format=json --no-report-file \
  | jq -r '.findings[] | "\(.id)  [\(.severity)] \(.title)"'
```

Expected: a structured explanation (What / Why / How to verify) in
plain language.

### 5. Apply a fix

```bash
hostveil fix <finding-id>
```

Expected:
- The program prints a preview of the change (file path, current
  line, proposed line).
- The program prompts for confirmation. Type `y` to apply.
- If the fix requires a service restart (e.g. `sshd`), the
  program prompts to restart. Type `y` to restart, `n` to defer
  (`restart_deferred=true` is recorded).
- A `FixRecord` is written to `state.db`.
- The program re-checks the affected category and prints a
  one-line confirmation that the finding is now resolved.

### 6. Roll back the fix

```bash
hostveil rollback <fix-record-id>
```

Find the id with:

```bash
hostveil scan --format=json --no-report-file \
  | jq -r '.findings[] | select(.state == "resolved") | .id'
```

Expected:
- The program prints a preview of the rollback.
- The program prompts for confirmation. Type `y`.
- The affected file is restored from the backup.
- A follow-up `FixRecord` is written with `procedure_used=rollback`
  and `rolled_back_via=<original id>`.

### 7. Verify the rollback is byte-identical

Before any fix, the integration test
`tests/integration/ssh_test.go` takes a SHA-256 of the affected
file. After `hostveil rollback`, the same test takes a second
SHA-256. The two must match exactly; this is the SC-003
contract.

Manual equivalent:

```bash
sha256sum /etc/ssh/sshd_config
# Apply and roll back a fix...
sha256sum /etc/ssh/sshd_config
# The two hashes must match.
```

Expected: identical hashes.

### 8. Re-run the scan

```bash
hostveil scan
```

Expected: the previously fixed finding is reported as
`resolved since last run` in the Summary section, and is not
counted in `new` or `still_present`. (Spec SC-004.)

---

## TUI tour

The TUI is a keyboard-driven interface over the same `state.db`
as the CLI. Run it from a real terminal (not over a pipe):

```bash
hostveil tui
```

Expected:
- The first paint shows a list of findings grouped by category
  and ordered by severity.
- `↓` / `j` move the selection; `Enter` / `e` expand the
  selected finding to its full explanation.
- `f` opens the "apply fix" flow with the same preview and
  confirmation as the CLI.
- `a` opens the "AI explain" side panel (only if `--ai` was
  passed at startup; otherwise a one-line hint).
- `?` toggles the help bar; `q` / `Ctrl+C` quits.

If you ran the TUI in a non-TTY context, the program prints
`hostveil tui requires a TTY; run from an interactive terminal`
and exits with code `0` (per FR-022).

The TUI is **optional** in v3.0.0; on a headless server, the
recommended install is the `notui` build (`go build -tags notui`).
The resulting binary is smaller and has no bubbletea dependency.

---

## Web UI tour

The Web UI is a localhost-bound dashboard. Start it:

```bash
hostveil web
```

Expected:
- The program prints a URL of the form
  `http://127.0.0.1:34567/`. Open it in a browser.
- The dashboard shows the most recent `ScanRun`, the findings
  list, and a "fix" button per finding.
- Clicking "fix" invokes the same `hostveil fix` flow as the
  CLI: a preview, an explicit confirmation, and a result
  message. The cookie scope is `Path=/`, `HttpOnly`,
  `SameSite=Strict`.
- Press `Ctrl+C` in the terminal to stop the server; the
  `WebSession` row is closed cleanly.

To expose the dashboard to a network (for example, to view it
on a phone on the same LAN):

```bash
hostveil web --bind 0.0.0.0:8443 --auth-token=$(openssl rand -hex 16)
```

Expected:
- The program refuses to start without `--tls-cert` and
  `--tls-key` (or with `--no-tls`). It generates a self-signed
  cert when those flags are absent.
- The console prints the URL, the auth token, and the TLS
  fingerprint. Paste the token into the browser's `/login` form
  to gain access.
- A request to any non-public route without a valid session
  cookie redirects to `/login`.

The Web UI is **optional** in v3.0.0; the recommended install
for a fully headless server is the `noweb` build
(`go build -tags noweb`).

---

## AI tour

The AI layer is opt-in and defaults to a local Ollama
provider. Verify Ollama is running:

```bash
curl -s http://localhost:11434/api/tags | head -1
```

Expected: a JSON response listing at least one model. If
Ollama is not running, see
[https://ollama.com](https://ollama.com) for installation.

### 1. Static (non-AI) explain

```bash
hostveil explain <finding-id>
```

Expected: a structured explanation in plain language, no
network call, no AI provider invocation.

### 2. AI explain (local provider)

```bash
hostveil ai explain <finding-id>
```

Expected:
- The program resolves the local Ollama provider (no consent
  prompt — `privacy_tier=local`).
- A redacted prompt is sent to `http://localhost:11434`.
- The response is printed to stdout.
- An `AIRequest` row is written to `state.db` for audit.

### 3. AI explain (cloud provider, first call)

```bash
export ANTHROPIC_API_KEY=sk-...
hostveil ai configure --provider=anthropic-prod \
  --kind=anthropic \
  --base-url=https://api.anthropic.com \
  --model=claude-3-5-sonnet-20241022 \
  --api-key-env=ANTHROPIC_API_KEY
hostveil ai explain <finding-id> --provider=anthropic-prod
```

Expected:
- The first call prints a one-time consent prompt that lists
  exactly which fields will be sent. The user must type `y`
  to proceed; the choice is recorded in the `AIProvider` row.
- Subsequent calls do not re-prompt.
- The response is printed to stdout.
- An `AIRequest` row is written with `redacted_prompt_sha256`
  and the provider / model.

### 4. Build the `noai` binary

```bash
go build -tags noai -trimpath -o dist/hostveil-noai ./cmd/hostveil
strings dist/hostveil-noai | grep -iE 'anthropic|openai|ollama' || echo "OK: no AI literals"
```

Expected: `OK: no AI literals`. The binary contains no AI
code, and any `hostveil ai` command prints "built without AI
support" and exits `2` (per FR-031 and SC-010).

### 5. Verify the fallback

```bash
# Stop the local Ollama server, then:
hostveil ai explain <finding-id>
```

Expected: the program prints the static explanation, a
one-line warning naming the failure class, and exits `0`
(per FR-033).

---

## Release validation

For v3.0.0 release candidates, the following sequence must pass on
at least one host per supported architecture. The CI pipeline
already runs the same sequence on a containerized test host (see
`test/hostimage/Dockerfile`); the manual run below is the
"smoke test on a real machine" step.

```bash
# 1. Build from the release tag.
git checkout v3.0.0
./scripts/build.sh
sha256sum dist/hostveil  # note for comparison

# 2. Reproduce the build on a second host and compare.
#    (Document the second host's host/arch/distro in the release notes.)
./scripts/build.sh
sha256sum dist/hostveil  # must match the first hash.

# 3. Run the test suite.
./scripts/test.sh        # runs unit + contract + integration.

# 4. Run the five-minute tour above on the current host.

# 5. Run on a host with deliberate misconfigurations
#    (the `test/hostimage/Dockerfile` is the canonical example).
docker build -t hostveil-test-host test/hostimage/
docker run --rm -it --privileged \
  -v /usr/local/bin/hostveil:/usr/local/bin/hostveil:ro \
  hostveil-test-host
# Inside the container, run the five-minute tour again.
```

Expected: every step in the tour produces the documented
"Expected" output, and the test suite passes with zero failures.

---

## Common failure modes (and what to do)

| Symptom | Likely cause | What to do |
|---|---|---|
| `unsupported platform: darwin` | Running on macOS | v3.0.0 is Linux-only. Run on a Linux host or in a Linux VM. |
| `hostveil: error: cannot acquire database lock after 5s` | Another `hostveil` invocation is running on the same user | Wait for the other run to finish, or kill it. |
| Scan runs but `hardening — firewall` is in the skipped list with `elevation_denied` | User not in `sudo` / `wheel` group, or sudoers file rejects the request | Re-run as a member of the elevation group, or accept the partial result for this run. |
| Scan runs but `image_cve` is `not_applicable` | No Docker containers on the host | Expected. Run on a host with Docker, or accept the result. |
| `hostveil fix` exits with `2: no built-in fix for <rule_id>` | The rule has a finding but no fix in v3.0.0 | Use `hostveil explain` for guidance, or post a request to add a fix in a v3.x release. |
| Report file is missing after a scan | `--no-report-file` was passed, or the report directory could not be created | Check `$HOME` permissions; the report is still on stdout. |
| `hostveil rollback` exits with `2: fix has no backup` | The fix did not support rollback (e.g. an image-pull fix) | The fix is permanent; the only way back is a manual `docker pull` of the previous tag. |

---

## Where to go next

- Architecture and threat model: `docs/how-it-works.md` (post-v3.0;
  for v3.0.0 the relevant design is in `research.md` and
  `data-model.md`).
- Contributing and dev setup: `docs/contributing.md` (post-v3.0;
  for v3.0.0 the build and test scripts are `scripts/build.sh` and
  `scripts/test.sh`).
- Public CLI reference: `contracts/cli.md`.
- Report format: `contracts/report.md`.
- SQLite schema: `contracts/state-db.md`.
