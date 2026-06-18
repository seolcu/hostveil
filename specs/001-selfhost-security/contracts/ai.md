# AI Provider Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document is the locked contract for the `internal/ai`
package and the public AI subcommands (Spec FR-028..FR-033).
It is enforced by `tests/contract/ai_test.go`.

All AI code is build-tag-gated: when `hostveil` is built with
the `noai` tag, the `ai` subcommand family is replaced by a
stub that prints "built without AI support" and exits `2` for
every AI-assisted command. The `strings` assertion in SC-010
verifies the binary contains no `(?i)anthropic|openai|ollama`
literal.

---

## Provider interface (Go)

```go
// internal/ai/ai.go
package ai

type Method string
const (
    MethodExplain   Method = "explain"
    MethodRisk      Method = "risk"
    MethodRecommend Method = "recommend"
)

type FindingSummary struct {
    ID            string
    Category      string
    RuleID        string
    Severity      string
    Title         string
    Description   string
    EntityRefs    []RedactedEntityRef
}

type Request struct {
    Method        Method
    Finding       FindingSummary
    HostContext   HostContext   // redacted
    UserQuestion  string        // optional; already redacted
}

type Response struct {
    Text          string
    TokensIn      *int
    TokensOut     *int
    LatencyMS     int
    Model         string
}

type Provider interface {
    Name() string
    PrivacyTier() PrivacyTier
    Call(ctx context.Context, req Request) (Response, error)
}
```

The `Provider` interface is small (one method) and is the only
exported surface of the package. The CLI / TUI / Web code calls
into `Provider.Call` via the registry in
`internal/ai/registry.go`.

---

## Public subcommands

```
hostveil ai explain <finding-id> [--provider=<name>] [--format=text|json]
hostveil ai risk    <finding-id> [--provider=<name>] [--format=text|json]
hostveil ai recommend <finding-id> [--provider=<name>] [--format=text|json]
hostveil ai configure [--provider=<name>] [--base-url=<url>] [--model=<id>] [--api-key-env=<name>]
hostveil ai list     [--format=text|json]
```

### `hostveil ai explain`

Returns the same plain-language explanation that
`hostveil explain` produces, but written by the AI provider.
The response is rendered to stdout (text) or as JSON
(`{response, model, tokens_in, tokens_out, latency_ms}`).

### `hostveil ai risk`

Returns a one-paragraph risk assessment tailored to the host's
context (e.g. "this finding is high risk because the SSH port
is exposed to the public internet per the firewall profile").
The AI's output is advisory; the program's own severity
classification is unchanged.

### `hostveil ai recommend`

Returns a one-paragraph fix recommendation. The recommendation
is NEVER applied automatically; the user must run
`hostveil fix <finding-id>` (CLI, TUI, or Web) explicitly. If
the user does run `hostveil fix` after a recommendation, the
`FixRecord` records `recommended_by=ai:<provider>:<model>` for
audit (FR-032).

### `hostveil ai configure`

Adds or updates a provider row in `state.db`'s `ai_providers`
table. The command is interactive (prompts for any missing
field) or non-interactive (all fields from flags). The
`--api-key-env` value is the name of an env var that holds the
key; the env var's value is NEVER persisted.

### `hostveil ai list`

Lists configured providers and their `enabled` / `consent_*`
state.

---

## Prompt contract (locked)

The redacted prompt that the program sends to any provider has
the following shape:

```text
You are a security advisor for a self-hosted Linux server. You are
helping a non-expert user understand a finding produced by Hostveil
v3.0.0, a security scanner.

Method: <explain|risk|recommend>
Finding:
  id:           <uuid>
  category:     <enum>
  rule_id:      <string>
  severity:     <enum>
  title:        <string>
  description:  <string>
  entity_refs:  <redacted>
Host context:
  os_family:    <enum>
  os_version:   <string>
  arch:         <enum>
  services:     <list of canonical service names>
User question: <string, optional>

Respond with a single paragraph in plain English. Do not include
file contents, secrets, or credentials. Do not issue shell commands.
Do not instruct the user to run any `hostveil fix` command by name;
instead, describe the change in plain language and let the user
choose.
```

The prompt is locked as a Go string constant in
`internal/ai/prompt.go`. The contract test
`tests/contract/ai_test.go` asserts that the prompt is exactly
this shape and that no field beyond the listed ones is ever
included.

The `entity_refs` field is the redacted form of the
`EntityRef` slice (path basename, not full path; container
image repo:tag without digest; CVE id only, no
description). The redaction list matches the one in
`contracts/report.md`.

---

## Redaction rules (locked)

The redaction list applied to every prompt (and to every
response, by symmetry, before it is shown to the user) is the
union of:

- The list in `contracts/report.md` (PEM private keys, named
  credential fields, URL credentials, AWS access keys).
- The whitelist in this contract: only the following fields
  are allowed in the prompt; everything else is dropped.
  - `method`
  - `finding.id`
  - `finding.category`
  - `finding.rule_id`
  - `finding.severity`
  - `finding.title`
  - `finding.description`
  - `finding.entity_refs[i].display` (but only the basename of
    the path; the full path is replaced by `<filename>:<line>`)
  - `host_context.os_family`
  - `host_context.os_version`
  - `host_context.arch`
  - `host_context.services` (canonical names only)
  - `user_question` (already redacted; the contract test
    asserts no PEM-style block is present)

The contract test asserts this whitelist on every test
invocation. Adding a field to the whitelist is a `schema_version`
bump in `contracts/report.md`.

---

## Consent flow (cloud providers only)

When the user runs any `hostveil ai <method> --provider=anthropic`
(or any other cloud provider) for the first time on a host,
the program prints a one-time consent prompt:

```
The AI call will send the following fields to <provider> at <base_url>:
  - finding.id
  - finding.category
  - finding.rule_id
  - finding.severity
  - finding.title
  - finding.description
  - finding.entity_refs[i].display (paths basenames only)
  - host_context.{os_family,os_version,arch,services}
  - user_question (if provided)

No file contents, secrets, credentials, environment variables, or
private keys are ever sent.

Proceed? [y/N]
```

The list is generated from the same whitelist that produces the
prompt; the user can see exactly what will be sent before they
type `y`. On `y`, the program's `AIProvider.consent_recorded_at`
is set and subsequent calls do not re-prompt. On `N` or
`Ctrl+C`, the call is aborted with exit `0`.

For the local Ollama provider, no consent prompt is shown
(`privacy_tier=local`).

---

## Failure modes and fallback (FR-033)

| Failure | Detection | Fallback behavior |
|---|---|---|
| Unreachable | `connection refused`, DNS failure, timeout | Static explanation with a one-line warning; exit `0`. |
| Timeout | `context.DeadlineExceeded` | Same. |
| Rate limit | HTTP 429 with `Retry-After` | After 3 failures in a 60 s window, fall back. The `AIRequest` row records the failure class. |
| Malformed response | JSON parse error, missing required fields | Discard the response, fall back. |
| Prompt-injection suspected | Response contains a regex match for `(?i)(run|execute)\s+(\`?rm\s+-rf\`?|curl\s+.*\|\s*sh|chmod\s+777\s+/)` or similar known-bad patterns | Discard, fall back, log the incident. |
| Auth failed | HTTP 401/403 | Print a clear message naming the env var / config key to set. No fallback; the user must fix the configuration. |
| Consent denied | User types `N` at the consent prompt | Exit `0` without a call. |
| `noai` build | The binary is built with the `noai` tag | Stub command prints a one-line message and exits `2`. |

The fallback is always the static explanation; the user never
sees an empty or partial response.

---

## Rate limiting (FR-033, expanded)

A per-provider token-bucket rate limiter, configured to allow
3 calls per 60-second sliding window. The limiter is in-memory
(not persisted) and resets on process restart. Exceeding the
limit produces the same fallback behavior as a `rate-limit`
failure above.

For the local Ollama provider, the limit is per-host, not
per-provider, to avoid penalizing the user for trying multiple
methods on the same finding.

---

## State persistence

- `AIProvider` rows are written by `hostveil ai configure` and
  read on every AI call.
- `AIRequest` rows are written for every call, success or
  failure. The redacted prompt's SHA-256 is recorded, not the
  prompt itself, to keep the audit trail useful without
  persisting what was sent.
- The consent state (`AIProvider.consent_recorded_at`) is the
  only state field that gates a future call.
