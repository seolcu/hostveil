# Feature Specification: Self-Host Security Scanner & Fixer

**Feature Branch**: `001-selfhost-security`
**Created**: 2026-06-18
**Status**: Draft
**Input**: User description: "As more and more people are selfhosting, for example like local LLM models via ollama, media server via Jellyfin, personal cloud via NextCloud, or even a Minecraft server... But not all those people are cybersecurity experts. So they are prone to misconfigurations and mistakes that can lead to very critical hackings. That can be: allowing root login via ssh, not using ssh, using an untrusted image or using an image with a lot of CVEs, or docker compose misconfigurations,... and so on. Therefore, I want to create a simple program for those people called Hostveil. It can scan the problems and fix it for them easily."

## Clarifications

### Session 2026-06-18

- Q: What is the v3 scan scope? → A: D — SSH + Docker + image CVEs + reverse proxy (nginx/caddy) + SSL/TLS + system hardening (firewall, fail2ban, unattended-upgrades, sysctl) all in v3.
- Q: How should Hostveil handle privileges (reading/writing system files owned by root)? → A: C — Auto-elevate via sudo/pkexec internally: the program detects which categories need elevation, prompts the user via the platform's standard elevation helper (sudo on most Linux distributions, pkexec where polkit is the convention), and runs only those categories elevated; on elevation failure, those categories are skipped with a clear message.
- Q: Where should the scan report go? → A: A — By default the program prints the full text report to stdout and also writes a copy to a file under a known per-user location (specifically `~/.local/share/hostveil/reports/`). The user can disable the file output with a flag.
- Q: Which version of Hostveil is this spec defining? → A: v3. v2.5.2 was the last released version of the previous implementation. v3 is a full rewrite from scratch: the v2.5.2 codebase MUST NOT be checked out, ported, mirrored, or referenced when making design or implementation decisions. The spec defines the v3 product on its own merits, and the released version is v3.0.0.
- Q: What user surfaces does v3 ship beyond the CLI? → A: TUI, Web UI, and AI features are all part of v3.0.0. The TUI is a keyboard-driven terminal interface (subcommand `hostveil tui`). The Web UI is a localhost-bound HTTP dashboard (subcommand `hostveil web`). AI features are advisory only (explanations, recommendations), are strictly opt-in per call, default to a local LLM provider (Ollama) for privacy, and MUST NOT be used to drive autonomous actions. Cloud AI providers are opt-in alternatives and require explicit user consent for any data leaving the host.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a one-shot security scan (Priority: P1)

A self-hoster who runs a homelab on a Linux server (for example running Ollama,
Jellyfin, NextCloud, or a Minecraft server) runs a single command. Within a
short, predictable time, the program reports what is wrong on their host in
plain language across every in-scope category (SSH, Docker, image CVEs, reverse
proxy, SSL/TLS, system hardening): which files or services are misconfigured,
which container images are known-vulnerable, which certificates are at risk, and
which system-level hardening checks are missing. The user gets a clear, ordered
list they can act on without having to be a security expert.

**Why this priority**: This is the core value of the product — turning opaque
host state into a prioritized list of concrete problems a non-expert can
understand. Without this, nothing else in the product is useful.

**Independent Test**: Can be fully verified by running the program against a
test host that is pre-seeded with each of the in-scope misconfigurations and
images, and observing that the report contains the expected items in plain
language, with each item tied to a real artifact on the host.

**Acceptance Scenarios**:

1. **Given** a host with `PermitRootLogin yes` in its SSH config, **When** the
   user runs the scan, **Then** the report lists "SSH allows root login" as a
   finding, names the affected config file and line, and explains the risk in
   non-technical terms.
2. **Given** a host running a Docker container whose image has a known CVE,
   **When** the user runs the scan, **Then** the report names the image, the
   affected container, and the CVE identifier, and ranks it alongside
   configuration findings.
3. **Given** a host with multiple independent misconfigurations, **When** the
   user runs the scan, **Then** the report presents findings grouped by
   category (SSH, Docker, images, etc.) and ordered by risk.
4. **Given** the user runs the scan with no arguments, **When** the scan
   completes, **Then** the program prints a one-line summary, the full report
   path, and exits with a status code that signals whether any
   high-severity findings were detected.

---

### User Story 2 - Apply a recommended fix safely (Priority: P2)

After reviewing the report, the user picks one or more findings and asks the
program to fix them. Before changing anything, the program shows exactly what
it is about to change in a form the user can read. The user can confirm, and
the program performs the change, records what it did, and (where possible)
saves a backup it can roll back to. If the user does not understand a
finding, they can ask for a plain-language explanation before deciding.

**Why this priority**: A scan that cannot lead to a fix is only half the
product. The "fix it for them easily" promise is the differentiator against
ad-hoc checklists and blog posts.

**Independent Test**: Can be verified by staging a host with a safe-to-revert
misconfiguration, requesting the corresponding fix, confirming the diff
preview, applying it, observing the host returns to a hardened state, and
then rolling back and observing the host returns to its original state.

**Acceptance Scenarios**:

1. **Given** a finding for which the program has a built-in fix,
   **When** the user requests the fix, **Then** the program shows a
   human-readable preview of the change (file path, current line, proposed
   line) and requires explicit confirmation before modifying anything.
2. **Given** the user confirms a fix, **When** the program applies it,
   **Then** the program records a timestamped entry describing what it
   changed and (where the file format permits) saves a backup the user can
   restore from.
3. **Given** the user requests a fix they do not understand,
   **When** they ask for an explanation, **Then** the program explains the
   finding and the proposed change in plain language, including what
   functionality might be affected.
4. **Given** a fix requires restarting a service,
   **When** the program applies the fix, **Then** the program tells the user
   which service will be restarted and lets them decline the restart.

---

### User Story 3 - Re-check the host after fixes (Priority: P3)

Some time after applying fixes, the user runs the program again to confirm
that the previous findings are gone and that no new issues have appeared
(for example because they pulled a new container image). The program shows
what changed since the last run so the user can see progress over time.

**Why this priority**: Self-hosted environments drift constantly — images
update, configs change, new services get added. Without a re-check loop,
the product's value decays the moment the user closes the report.

**Independent Test**: Can be verified by applying one fix, re-running the
program, and observing that the original finding is now marked as resolved
and a small change log is produced.

**Acceptance Scenarios**:

1. **Given** the user has previously run the program at least once,
   **When** they run it again, **Then** the report distinguishes between
   "new", "still present", and "resolved since last run" findings.
2. **Given** the user applies a fix and then re-runs the program,
   **When** the scan completes, **Then** the corresponding finding is
   marked as resolved and the count of unresolved findings decreases.
3. **Given** the user pulls a new image with a known CVE,
   **When** they re-run the program, **Then** that image appears as a new
   finding with the CVE identifier and its severity.

---

### User Story 4 - Explore findings in an interactive TUI (Priority: P2)

After running one or more scans, the user wants a faster way to explore
findings, read explanations, and queue fixes than scrolling through
the text report. The user runs `hostveil tui` and gets a
keyboard-driven terminal interface that shows findings grouped by
category and severity, lets the user expand each finding for a
plain-language explanation, and lets the user select findings to
queue for a fix. The TUI is single-host and works over SSH; it does
not require a graphical display.

**Why this priority**: A non-expert user running the program for
the first time will look at a long report and feel overwhelmed. A
TUI that highlights the top finding and explains it in plain
language dramatically reduces the time-to-first-fix.

**Independent Test**: Can be verified by running the program in a
PTY (e.g. `script` or `expect`) against a pre-seeded host and
observing that the TUI renders the expected finding list, that
keyboard navigation moves between findings, and that selecting
"explain" shows the plain-language explanation.

**Acceptance Scenarios**:

1. **Given** a host with at least one finding in `state.db`,
   **When** the user runs `hostveil tui` in a TTY, **Then** the
   TUI renders a navigable list of findings grouped by category
   and ordered by severity.
2. **Given** the TUI is showing a finding, **When** the user
   presses the "explain" key, **Then** the TUI shows the same
   plain-language explanation that `hostveil explain` produces,
   and offers an "AI explain" action when AI is enabled.
3. **Given** the user has selected one or more findings in the TUI,
   **When** the user presses "apply fix", **Then** the TUI invokes
   the same `hostveil fix` flow as the CLI (preview, confirmation,
   backup, apply, re-check) and shows the result.
4. **Given** the user runs `hostveil tui` in a non-TTY context
   (stdin or stdout is not a terminal), **When** the subcommand
   starts, **Then** it prints a one-line message explaining the
   TUI requires a TTY and exits with code `0` without error.

---

### User Story 5 - View findings in a local web dashboard (Priority: P3)

Some users prefer a graphical view: a small dashboard they can open
in a browser, see findings over time, and apply fixes with a click.
The user runs `hostveil web` and the program starts a small HTTP
server. The user opens the printed URL in a browser and gets a
dashboard with the same data as the TUI, plus a small history
chart. The web UI is bound to localhost (127.0.0.1) by default; if
the user explicitly opts in to binding on a public interface, the
program generates a one-time random URL token printed to the
console that the user must present in the browser to gain access.

**Why this priority**: A web dashboard is the most natural
presentation for users who are already working in a browser, but
it is also the most security-sensitive surface (network exposure,
authentication, CSRF). Lower priority lets the security review
land after the TUI proves the core UX.

**Independent Test**: Can be verified by running the web
subcommand against a pre-seeded host, opening the printed URL in
a headless browser, observing the dashboard renders the expected
findings, and clicking "apply fix" to confirm the same fix flow
runs as the CLI.

**Acceptance Scenarios**:

1. **Given** the user runs `hostveil web` with no flags,
   **When** the server starts, **Then** it binds to
   `127.0.0.1:<random-port>`, prints the URL, and serves the
   dashboard.
2. **Given** the web UI is open, **When** the user clicks
   "apply fix" on a finding, **Then** the dashboard invokes the
   same fix flow as the CLI: it shows the preview, requires an
   explicit confirmation, and on success shows the result and the
   backup path.
3. **Given** the user passes `--bind 0.0.0.0:8080` to expose the
   dashboard to the network, **When** the server starts, **Then**
   the program refuses to start unless `--auth-token` is also
   provided, and serves over HTTPS using a self-signed certificate
   (or the user-provided cert/key pair).
4. **Given** the web UI is open and the user's session token is
   missing or invalid, **When** the user navigates to any
   non-public route, **Then** the dashboard shows a "session
   expired, restart `hostveil web`" message and does not leak any
   finding data.

---

### User Story 6 - Get AI-assisted explanations and recommendations (Priority: P3)

Some findings are hard to explain in pre-written text, especially
when the user's setup is unusual. The user can opt in to AI
assistance: instead of the static explanation, the program asks an
AI provider for a richer, contextualized explanation. AI assistance
is also useful for risk assessment (how urgent is this finding for
*this* host's setup) and for fix recommendations (which of the
multiple ways to fix this would be safest for my use case).

The AI is strictly opt-in per call. The default provider is a
local LLM (Ollama) running on the user's own machine, so no host
state leaves the host. If the user wants a more capable cloud
provider (e.g. Anthropic Claude), they configure it explicitly
and consent to redacted data being sent. AI responses are
advisory: the program NEVER applies a fix based on AI guidance
without the same explicit user confirmation as any other fix.

**Why this priority**: AI features materially improve UX for
non-experts, but they introduce network exposure, privacy
concerns, and non-determinism. They land at P3 so the
non-AI surfaces ship first and the AI surface is reviewed against
real usage.

**Independent Test**: Can be verified by running the program with
AI enabled against a finding, observing that an AI provider is
called, and confirming that the prompt sent to the provider
contains only redacted finding metadata (no secrets, no file
contents). For cloud providers, the same test must be repeated
with the network egress log to confirm no secrets or sensitive
content crossed the wire.

**Acceptance Scenarios**:

1. **Given** the user has the local Ollama provider configured
   and a finding in `state.db`, **When** the user runs
   `hostveil explain <finding-id> --ai`, **Then** the program
   sends a redacted prompt to `http://localhost:11434` and prints
   the AI's explanation.
2. **Given** the user runs `hostveil explain <finding-id> --ai
   --provider=anthropic` and has not previously consented to data
   leaving the host, **When** the command runs, **Then** the
   program prints a one-time consent prompt that lists exactly
   what will be sent, and refuses to proceed until the user
   confirms.
3. **Given** the AI provider is unreachable, **When** the user
   runs an AI-assisted command, **Then** the program falls back
   to the non-AI explanation, prints a clear warning, and exits
   with code `0`.
4. **Given** the user runs `hostveil fix <finding-id>` after an
   AI recommendation, **When** the fix command runs, **Then** the
   fix flow is identical to a non-AI fix: preview, confirmation,
   backup, apply, re-check. The AI recommendation is logged in
   the `FixRecord` as a `recommended_by` field for audit, but is
   not used to bypass any confirmation.

---

### Edge Cases

- **No network available**: the program MUST still be able to scan host
  configuration locally. CVE lookups that require a remote feed MUST be
  skipped gracefully and the report MUST indicate which findings could not
  be enriched with remote data.
- **No CVE feed match**: an image that is not present in the vulnerability
  feed MUST be reported as "unknown vulnerability status" rather than
  silently treated as safe.
- **Insufficient privileges**: findings that require elevated privileges
  (for example reading system SSH config) MUST be skipped with a clear
  message indicating how to re-run with sufficient privileges, instead of
  failing silently or crashing.
- **Conflicting findings**: when a built-in fix would conflict with an
  existing user intent (for example the user has explicitly enabled root
  SSH login for a documented reason), the program MUST surface the
  conflict and require an explicit override, not silently override the
  user's existing configuration.
- **Broken Docker environment**: if Docker is not installed, not running,
  or the user has no containers, the program MUST still report on the
  rest of the host and note that Docker scanning was skipped.
- **Custom SSH config locations**: the program MUST support non-default
  SSH config paths and MUST NOT assume `/etc/ssh/sshd_config`.
- **Partial fix failure**: if a multi-step fix partially succeeds, the
  program MUST report exactly which steps succeeded, which failed, and
  what state the host is currently in, and MUST attempt to roll back
  completed steps where rollback is supported.
- **No reverse proxy installed**: the program MUST skip the reverse
  proxy category cleanly when nginx or caddy are not present, and MUST
  NOT report the absence itself as a finding.
- **Custom firewall backend**: the program MUST detect whether `ufw`,
  `iptables`, or `nftables` is the active backend and adapt its checks
  accordingly, and MUST NOT assume a specific backend is in use.
- **Expired or malformed TLS certificate**: the program MUST report
  the expiration in a human-readable form (for example "expires in 3
  days" or "expired 12 days ago") and MUST NOT crash when certificate
  metadata cannot be parsed.
- **Update check without usable metadata**: the program MUST skip the
  security-update check when no package metadata is available (offline
  or unsupported distribution), and MUST clearly label the
  corresponding finding as not-checked.
- **Elevation prompt denied or failed**: when the user declines the
  platform's elevation prompt, or the helper fails (wrong password,
  helper not installed, user not in the elevation group), the program
  MUST skip the affected category with a clear message, MUST NOT
  crash, and MUST continue scanning the remaining categories without
  elevation.
- **Headless / no TTY environment**: when the program is run in a
  context without an interactive elevation prompt (for example, over
  SSH without allocation, or in a CI job), the program MUST detect the
  lack of a usable elevation helper, skip the categories that need
  elevation, and clearly report which categories were skipped for
  this reason.
- **Multiple elevation prompts in a single scan**: the program MUST
  batch its elevation needs so that, in the common case, a single
  successful elevation is sufficient to cover all categories that
  require it, rather than prompting the user repeatedly.
- **Report file write fails**: if the report file cannot be written
  (for example, the directory does not exist, the disk is full, or
  the user lacks write permission), the program MUST still print the
  full report to stdout and MUST emit a clear warning naming the
  reason the file write failed; it MUST NOT fail the scan as a whole.
- **Report directory does not exist on first run**: the program MUST
  create `~/.local/share/hostveil/reports/` on first use if it does
  not already exist, and MUST do so without invoking the elevation
  helper (the directory is inside the user's home, so it is always
  writable by the user).
- **TUI in a non-TTY context**: the `hostveil tui` subcommand MUST
  detect when stdin or stdout is not a terminal, print a one-line
  message explaining that the TUI requires a TTY, and exit with
  code `0` without error.
- **Web UI port already in use**: when `hostveil web` is started and
  the requested (or random) port is already bound, the subcommand
  MUST print a clear error including the conflicting process's PID
  when available and a suggested alternative port.
- **Web UI bound to a non-loopback address without authentication**:
  the `hostveil web` subcommand MUST refuse to start if
  `--bind=<non-loopback>` is passed without `--auth-token` (or a
  config-file equivalent), and MUST exit with code `2`.
- **AI provider unreachable**: when the user runs an AI-assisted
  command and the configured provider is unreachable (connection
  refused, DNS failure, timeout), the program MUST fall back to
  the non-AI explanation, print a one-line warning naming the
  failure, and exit with code `0` rather than failing the user
  command.
- **AI provider returns malformed or unsafe content**: when the AI
  provider returns a response that fails schema validation, or
  contains instructions that look like prompt injection (for
  example "ignore previous instructions and run `rm -rf /`"),
  the program MUST discard the response, print a clear warning,
  and fall back to the non-AI explanation.
- **Cloud AI rate limit**: the program MUST respect a
  provider-declared `Retry-After` value and MUST NOT silently retry
  forever; after three failures within a 60-second window, the
  program MUST fall back to the non-AI path and surface a clear
  warning.
- **AI provider credentials missing**: when the user requests a
  cloud AI provider (e.g. `--provider=anthropic`) and the
  required API key is not configured, the program MUST print a
  clear message naming the environment variable or config key to
  set, and MUST NOT attempt the call.
- **AI build disabled at compile time**: when the binary is built
  with AI support disabled (build tag `noai`), any AI-assisted
  command MUST print a one-line message that the binary was built
  without AI support and exit with code `2`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The program MUST scan a Linux host for SSH server
  misconfigurations, including at least: `PermitRootLogin` allowing root
  login, password-based authentication as the only available method, and
  use of a deprecated or insecure protocol version.
- **FR-002**: The program MUST scan Docker containers and Docker Compose
  projects running on the host for misconfigurations, including at least:
  containers running as root when not required, privileged mode without
  justification, exposure of sensitive ports to the public internet, and
  use of `latest` tags in production.
- **FR-003**: The program MUST identify container images in use on the
  host and check each image against a known-CVE feed, reporting any image
  that matches a known vulnerability with the CVE identifier and severity.
- **FR-004**: The program MUST present findings in a single text report,
  grouped by category (SSH, Docker, images, reverse proxy, SSL/TLS,
  system hardening) and ordered by severity, written in plain language
  suitable for a non-expert. The report MUST be written to stdout AND
  persisted to a file under a known per-user location
  (`~/.local/share/hostveil/reports/`), and the user MUST be able to
  disable the file output with a flag.
- **FR-005**: The program MUST support a command that applies a built-in
  fix for a single finding, and MUST require explicit user confirmation
  after displaying a human-readable preview of the proposed change.
- **FR-006**: The program MUST record, for every applied fix, a timestamp,
  a description of the change, the affected file path, and (where the file
  format permits) a backup path the user can use to roll back.
- **FR-007**: The program MUST support a command that rolls back a
  previously applied fix using its recorded backup, where a backup exists.
- **FR-008**: The program MUST persist a history of its runs and findings
  on the local host, and MUST use that history to label findings as new,
  still present, or resolved when re-run.
- **FR-009**: The program MUST be runnable as a single, documented
  command on a stock Linux server with only the prerequisites the user is
  told about up front, and MUST NOT require the user to install or learn
  any extra framework, runtime, or service to run a scan.
- **FR-010**: The program MUST explain any single finding and any single
  proposed fix in plain language on demand, without requiring the user to
  read source code, documentation files, or external references.
- **FR-011**: The program MUST surface conflicts between a proposed fix
  and the user's existing configuration, and MUST require explicit
  override before proceeding in that case.
- **FR-012**: The program MUST surface prerequisites for each scan category
  (for example, the ability to read `/etc/ssh/sshd_config`) and MUST
  attempt to satisfy any elevation prerequisite through the platform's
  standard helper (sudo on most Linux distributions, pkexec where
  polkit is the convention). If elevation succeeds, the category is
  scanned; if the user declines the elevation prompt or the helper
  fails, the program MUST skip that category with a clear message
  rather than crashing.
- **FR-013**: The program MUST be runnable offline for the parts of the
  scan that do not require remote data, and MUST clearly mark any finding
  that could not be enriched with remote data.
- **FR-014**: The program MUST scan reverse proxy configurations
  (nginx, caddy) for at least: server tokens leaking version information,
  missing common security response headers, exposure of sensitive hidden
  paths (for example `.git`, `.env`, `.htpasswd`), and absence of rate
  limiting on authentication endpoints.
- **FR-015**: The program MUST check the host's TLS certificates for
  expiration, the presence of an auto-renewal mechanism, and the
  supported TLS protocol versions on any detected exposed endpoint.
- **FR-016**: The program MUST scan system-level hardening: the active
  firewall backend and its default policy and rule set, the presence
  and active jails of fail2ban, the configuration of unattended-upgrades,
  and a baseline of sysctl security-relevant settings (IP forwarding,
  SYN cookies, ASLR, and similar).
- **FR-017**: The program MUST detect whether the host has pending
  security updates and report their count and severity; this check MUST
  be skippable, MUST work offline (using cached package metadata), and
  MUST clearly label findings as not-checked when no metadata is
  available.
- **FR-018**: When the program invokes the platform's elevation helper
  (sudo or pkexec) on the user's behalf, it MUST clearly explain in
  plain language which category is being elevated and why, MUST scope
  the elevated operation to the minimum commands needed for that
  category, and MUST NOT retain elevated privileges beyond the lifetime
  of the elevated sub-process.
- **FR-019**: The report file path MUST follow the XDG Base Directory
  specification (`~/.local/share/hostveil/reports/`), MUST be unique
  per scan run (timestamped filename), MUST be readable by the
  invoking user, and MUST NOT be written to any location outside the
  user's home directory (no `/tmp`, no system paths) without explicit
  opt-in.
- **FR-020**: The program MUST treat the persisted report file as
  user-private state: it MUST NOT include secrets, credential
  material, or any value that could be used to authenticate as the
  user, and MUST redact any such values if they are encountered
  during scanning.
- **FR-021**: The program MUST ship an interactive Terminal User
  Interface (TUI) under the `hostveil tui` subcommand, built on
  the bubbletea framework, that provides keyboard-driven
  navigation of findings grouped by category and ordered by
  severity, with per-finding "explain" and "apply fix" actions.
- **FR-022**: The TUI MUST be operable over SSH (no graphical
  display required), MUST NOT require a mouse, and MUST degrade
  gracefully to a one-line message and a `0` exit code when
  invoked outside a TTY.
- **FR-023**: The TUI MUST share its data layer with the CLI: the
  findings it shows MUST come from the same `state.db` and MUST
  be the same `Finding` rows that `hostveil scan` produced.
- **FR-024**: The program MUST ship a Web User Interface under the
  `hostveil web` subcommand, implemented as a small local HTTP
  server using only the Go standard library (`net/http`,
  `html/template`) plus a small client-side JavaScript helper
  (HTMX), that renders a single-page dashboard of the most
  recent `ScanRun`, its `Finding`s, and a fix action per
  finding.
- **FR-025**: The web server MUST bind to `127.0.0.1` on a random
  free port by default, MUST refuse to start on a non-loopback
  address without `--auth-token=<random>` (or a config-file
  equivalent), and MUST serve over HTTPS with a self-signed
  certificate (or a user-provided cert/key pair) whenever it
  binds to a non-loopback address.
- **FR-026**: The web server MUST generate a one-time random
  session token at startup, print it to the console, and require
  the user to present it in the browser before any non-public
  route is reachable. The session token MUST be valid for the
  lifetime of the web process and MUST be discarded on shutdown.
- **FR-027**: The web dashboard MUST be read-only by default; the
  "apply fix" action MUST invoke the same fix flow as the CLI
  (preview, confirmation, backup, apply, re-check) and MUST NOT
  bypass any of those steps.
- **FR-028**: The program MUST support an AI provider abstraction
  behind a single Go interface, with two first-class adapters in
  v3.0.0: a local LLM provider speaking the Ollama HTTP API
  (default), and a cloud provider speaking the Anthropic
  Messages API. Additional providers are pluggable but out of
  scope for v3.0.0.
- **FR-029**: AI features MUST be opt-in per call (e.g. `--ai` on
  `explain`, `recommend`, or `risk` subcommands) and MUST NOT
  make any network call in the default scan / fix / rollback
  path.
- **FR-030**: When the user selects a cloud AI provider, the
  program MUST print a one-time consent prompt that lists
  exactly what fields will be sent (finding category, rule id,
  severity, redacted entity references; never file contents,
  secrets, or credential material), and MUST refuse to proceed
  until the user explicitly confirms.
- **FR-031**: The program MUST be buildable with a `noai` build
  tag that excludes all AI code from the binary; binaries built
  with `noai` MUST reject any AI-assisted command with a
  one-line message and exit code `2`.
- **FR-032**: AI responses MUST be advisory only. The program
  MUST NOT apply any fix based solely on an AI recommendation;
  the same explicit user confirmation required for any fix is
  also required after an AI recommendation, and the
  recommendation is recorded on the `FixRecord` as
  `recommended_by=ai:<provider>:<model>` for audit.
- **FR-033**: When an AI provider call fails (unreachable,
  timeout, rate limit, malformed response, prompt-injection
  suspected), the program MUST fall back to the non-AI
  explanation or recommendation, print a one-line warning naming
  the failure class, and exit with code `0`.

### Key Entities

- **Host**: the Linux machine the program is run against. Has identity
  (hostname, OS family and version), a set of `Service`s it runs, and a
  set of `ConfigFile`s the program inspects.
- **Service**: a long-running process the host exposes, such as an SSH
  server, a Docker daemon, or a named application (Ollama, Jellyfin,
  NextCloud, Minecraft server). Has a name, a status, and the `ConfigFile`s
  that govern it.
- **ConfigFile**: a file on disk the program inspects, such as
  `sshd_config` or a `docker-compose.yml`. Has a path, an owner, a
  format, and a set of `Setting`s.
- **Setting**: a key/value pair inside a `ConfigFile`, with the line
  number, the configured value, and the value the program considers safe.
- **ContainerImage**: a Docker image in use on the host, identified by
  name and digest. Has a set of `Vulnerability` matches against the
  known-CVE feed.
- **Vulnerability**: a known CVE. Has an identifier, a severity, a
  short description, and a list of affected `ContainerImage`s.
- **Finding**: a single problem the program reports. Has a category, a
  severity, a plain-language title, a plain-language description, a list
  of affected `Entity` references (Host, Service, ConfigFile, Setting,
  ContainerImage, Vulnerability), and an optional built-in `Fix`.
- **Fix**: a remediation the program can apply for a `Finding`. Has a
  description, a preview of the change, a procedure the program can
  execute, a rollback procedure (where supported), and a list of services
  that must be restarted.
- **FixRecord**: a persistent record of a `Fix` that has been applied.
  Has a timestamp, the `Finding` it addresses, the affected `ConfigFile`,
  the backup path, and the procedure used.
- **ScanRun**: a single execution of the scan. Has a timestamp, the host
  it ran against, the categories that were scanned, the categories that
  were skipped (and why), and the `Finding`s produced.
- **ReverseProxy**: a web-facing proxy the host runs, such as nginx or
  caddy. Has a name, a detected version, a list of `VHost` configs, and
  the `ConfigFile` that defines it.
- **VHost**: a single virtual host defined by a `ReverseProxy`. Has a
  server name, a list of exposed locations, and security-relevant
  `Setting`s.
- **SSLCertificate**: a TLS certificate observed on an exposed endpoint
  or in a `ConfigFile`. Has a path (when applicable), an issuer, an
  expiration date, and a renewal mechanism (if any).
- **FirewallProfile**: the host's firewall state. Has a backend
  (`ufw`, `iptables`, `nftables`, or none), a default policy, and a
  list of `FirewallRule`s.
- **HardeningBaseline**: a set of system-level security checks. Has a
  list of `sysctl` keys and expected values, a list of expected-present
  security packages, and a list of expected services.
- **SystemUpdateStatus**: whether the host has pending security updates.
  Has a count, a list of affected packages, and a last-checked
  timestamp.
- **TUISession**: a single `hostveil tui` invocation. Has a start
  time, the host it was opened against, the count of findings the
  user expanded, the count of fix actions the user triggered,
  and an exit reason (`user-quit`, `no-tty`, `internal-error`).
- **WebSession**: a single `hostveil web` invocation. Has a start
  time, the bind address, the port, the auth token's SHA-256
  (never the token itself), a TLS-fingerprint (when HTTPS is
  served), a count of dashboard views, and a count of fix
  actions triggered.
- **AIProvider**: the configuration of an AI provider. Has a
  `kind` enum (`ollama`, `anthropic`, `custom`), a `base_url`,
  a `model`, an `api_key_ref` (a reference to an env var or
  config key, never the key itself), a `privacy_tier` enum
  (`local`, `cloud-self-hosted`, `cloud-vendor`), and a
  `consent_required` boolean (true for any cloud tier).
- **AIRequest**: a single AI call. Has a timestamp, the
  `AIProvider` used, the `model`, the redacted prompt, the
  response text (or the error class), a `tokens_in` and
  `tokens_out` count (when the provider reports them), and a
  `latency_ms` measurement. Persisted for audit and for the
  per-call rate-limit state.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A non-expert user can complete a full scan of their host,
  read the report, and select at least one finding to fix, in under 5
  minutes of total wall-clock time, with no prior training on the
  program.
- **SC-002**: At least 95% of findings produced on a representative
  test host are reproducible by a second run of the program within one
  hour, where the host has not been modified between runs.
- **SC-003**: When the user applies a built-in fix that has a recorded
  backup, rolling back returns the affected configuration file to the
  byte-identical contents it had immediately before the fix, verified by
  checksum comparison.
- **SC-004**: A second run of the program after applying fixes MUST show
  each previously fixed finding as "resolved" and MUST NOT re-report the
  same issue as a new finding, for as long as the host configuration has
  not changed.
- **SC-005**: The program MUST produce a report that is fully readable
  end-to-end on a standard terminal (no more than 120 columns wide), and
  MUST NOT require an internet connection to display its core findings
  once the vulnerability feed has been refreshed.
- **SC-006**: In a usability test with at least 5 self-hosters
  self-identifying as non-experts, at least 4 of 5 can describe, in
  their own words, what the program's top-priority finding means and
  what the proposed fix changes, immediately after reading the report.
- **SC-007**: A non-expert user can complete a TUI session
  (open, navigate to the top finding, read the explanation, queue
  a fix, confirm, and quit) in under 2 minutes with no prior
  training, on a host with at least 10 findings, using only
  keyboard input.
- **SC-008**: The web UI dashboard MUST load its first paint (the
  initial findings list) in under 2 seconds on a local connection
  to a host with 100 findings, and MUST remain responsive
  (interactions under 200 ms) for any subsequent navigation.
- **SC-009**: An AI-assisted `hostveil explain` call against a
  configured local Ollama provider MUST return a non-empty
  response in under 30 seconds on a host with a modern CPU and
  16 GB RAM, and the program's fallback to the non-AI
  explanation MUST be reachable in under 1 second when the
  provider is unreachable.
- **SC-010**: The program MUST be buildable in three
  configurations: (a) full (CLI + TUI + Web + AI), (b)
  `noai` (CLI + TUI + Web, AI code excluded), and (c)
  `noai-notui` (CLI + Web, no TUI, no AI). The `noai`
  binary MUST contain no string literal that matches
  the regex `(?i)anthropic|openai|ollama` (verified by
  `strings` over the binary).

## Assumptions

- **Version context**: this specification defines v3 of Hostveil, a
  full rewrite. The previous released version was v2.5.2. The v2.5.2
  codebase MUST NOT be checked out, ported, mirrored, or used as a
  design reference for v3; v3 is specified on its own merits, and the
  first v3 release is v3.0.0.
- The user is on a Linux host. macOS and Windows hosts are out of scope
  for v3; the program will print a clear "unsupported platform" message
  on non-Linux systems.
- The user has shell access to the host they want to scan and is in
  the system group that allows elevation (for example, the `sudo` or
  `wheel` group) when the program needs to read or write system-owned
  files. The program itself drives the elevation flow through the
  platform's standard helper (sudo on most Linux distributions, pkexec
  where polkit is the convention) and does not require the user to
  pre-elevate the program.
- The user has, or is willing to have, Docker installed when they want
  the Docker-related parts of the scan. Absence of Docker is a
  skipped category, not a failure.
- "Self-hosted" in this context means services the user runs directly
  on a Linux server or inside Docker on that server. Cloud-managed
  services (for example, a hosted Nextcloud instance) are out of scope
  for v3.
- A known-CVE feed is available to the program. The feed source,
  freshness guarantees, and offline caching behavior are implementation
  details and are decided during planning, not specification.
- "Fix" means modifying a configuration file or running a documented
  remediation command. Replacing a vulnerable image with a non-vulnerable
  one is a class of fix the program can recommend, but the actual image
  pull and container recreation may require user confirmation beyond a
  simple "apply".
- The user understands that no automated scanner can guarantee a host
  is "secure", and the program frames its output as a prioritized list
  of known issues, not as a security guarantee.
- **TUI environment**: the TUI requires a real terminal (TTY). It
  does not work over a pipe, in a non-interactive `ssh` session
  without a TTY allocation, or in a CI job. In those contexts,
  the user is expected to use the CLI subcommands directly.
- **Web UI is local-first**: the web UI binds to `127.0.0.1` on a
  random free port by default. Exposing it to a network is an
  explicit, opt-in action that requires both an auth token and
  HTTPS. The web UI is not a multi-tenant system; it is a
  single-user dashboard for the host it runs on.
- **AI is opt-in and local by default**: the v3.0.0 release ships
  with a local LLM provider (Ollama) as the default AI backend.
  No AI call is ever made in the default `scan`, `fix`, or
  `rollback` paths; the user must pass `--ai` to opt in to a
  single AI-assisted action. Cloud providers (Anthropic) are an
  opt-in alternative and require explicit one-time consent that
  names exactly what fields will be sent.
- **AI is not a source of authority**: AI responses are advisory
  only. The program never applies a fix based solely on an AI
  recommendation; the same explicit user confirmation required
  for any fix is also required after an AI recommendation, and
  the recommendation is recorded on the `FixRecord` for audit.
  This is a hard product boundary, not a tunable preference.
