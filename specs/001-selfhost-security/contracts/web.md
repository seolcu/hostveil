# Web UI Contract: Hostveil v3.0.0

**Phase**: 1 (Design & Contracts)
**Date**: 2026-06-18
**Spec**: [spec.md](../spec.md)
**Plan**: [plan.md](../plan.md)
**Data Model**: [data-model.md](../data-model.md)
**Research**: [research.md](../research.md)

This document is the locked contract for the `hostveil web`
subcommand (Spec FR-024..FR-027). It is enforced by
`tests/contract/web_test.go` (which uses `net/http/httptest` to
drive the handlers and assert on responses).

The Web UI is build-tag-gated: when `hostveil` is built with the
`noweb` tag, the `web` subcommand is replaced by a stub that
prints a one-line "built without Web UI" message and exits `0`.

---

## Invocation

```
hostveil web [flags]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--bind` | addr | `127.0.0.1:0` (random port) | Address to bind. Loopback only by default. |
| `--auth-token` | string \| empty | random UUIDv4 | Required when `--bind` is a non-loopback address. When binding to loopback, the token is still generated and printed (so the user can paste it in the browser to enable a future network bind without restarting). |
| `--tls-cert` | path \| empty | auto-generated self-signed | TLS certificate. Required when binding non-loopback. |
| `--tls-key` | path \| empty | required with `--tls-cert` | TLS private key. |
| `--no-tls` | bool | false | Disable TLS even on non-loopback binds. The program refuses to start if `--no-tls` is combined with a non-loopback bind. |
| `--read-only` | bool | false | Disable the "apply fix" action; the dashboard becomes read-only. Useful for kiosk / display setups. |

### Startup behavior

1. Resolve `--bind`. If it is non-loopback, verify that
   `--auth-token` is set (or generated) and that TLS is
   configured. On any of these failures, exit `2` with a
   clear error (per FR-025, FR-026).
2. Generate the session token if not provided (a 32-byte
   cryptographically random value, hex-encoded).
3. Generate a self-signed TLS certificate if `--tls-cert` is
   not provided and the bind is non-loopback. The certificate's
   CN and SANs are derived from the hostname; the program
   prints the cert's SHA-256 fingerprint at startup so the
   user can pin it.
4. Open a `WebSession` row in the database (started_at = now,
   bind address, is_loopback, auth_token_sha256,
   tls_fingerprint).
5. Start the HTTP server. On any listen error, exit `2`.
6. Print the URL and the auth token (if any) to the console:
   ```
   Hostveil v3.0.0 web UI
   URL:           https://127.0.0.1:34567/
   Auth token:    a1b2c3d4-...  (paste into the login form)
   TLS fp:        SHA256:...
   Session:       1.5h uptime, 0 dashboard views, 0 fix actions
   ```
7. Block until SIGINT or SIGTERM, then close the `WebSession`
   row with `ended_at` and `exit_reason=user-quit`.

---

## HTTP routes (locked)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` | optional | Dashboard root. If unauthenticated and a token is required, redirects to `/login`. |
| GET | `/login` | none | Login form. Accepts the session token and sets a session cookie. |
| POST | `/login` | none | Accepts `token=<value>`; on success sets `hostveil_session=<cookie>` and redirects to `/`. |
| POST | `/logout` | session | Clears the session cookie and redirects to `/login`. |
| GET | `/api/v1/host` | session | JSON: the current host's identity. |
| GET | `/api/v1/runs` | session | JSON: the most recent `ScanRun` rows, newest first. |
| GET | `/api/v1/runs/{id}` | session | JSON: a single `ScanRun` and its `Finding`s. |
| GET | `/api/v1/findings` | session | JSON: the most recent `Finding` rows. Supports `?category=`, `?severity=`, `?state=`. |
| GET | `/api/v1/findings/{id}` | session | JSON: a single `Finding` with its full plain-language explanation. |
| GET | `/api/v1/fixes` | session | JSON: the most recent `FixRecord` rows. |
| POST | `/api/v1/fixes/{finding_id}/preview` | session | JSON: the same preview string that `hostveil fix` would print. |
| POST | `/api/v1/fixes/{finding_id}/apply` | session | JSON: applies the fix; same body shape as the CLI. |
| POST | `/api/v1/fixes/{fix_record_id}/rollback` | session | JSON: rolls back a previously applied fix. |
| GET | `/api/v1/ai/explain/{finding_id}` | session | JSON: invokes the AI provider (per `contracts/ai.md`); returns the response or the fallback marker. |
| GET | `/healthz` | none | Liveness probe: returns `200 OK` with body `{"status":"ok"}`. |
| GET | `/static/*` | session | Vendored assets (HTMX helper, CSS, JS). No remote fetches. |

Routes that take a session check the `hostveil_session` cookie
against a value derived from the auth token's SHA-256 plus a
server-side random nonce stored in memory (so a stolen cookie
without the token is useless).

---

## Authentication

The auth token is required only when the bind is non-loopback.
For loopback binds, the session cookie alone is accepted (this
matches the spec's "single-user dashboard" assumption and
mirrors the model of `psql`, `mongosh`, etc. that bind to
loopback and trust the local user).

When auth is required:

- The login form (`GET /login`) shows a single text field
  labeled "Session token" and a submit button.
- On `POST /login`, the program compares the submitted token
  against the in-memory session token using a constant-time
  comparison.
- On success, it sets a `hostveil_session` cookie scoped to
  `Path=/`, `HttpOnly`, `Secure` (when TLS is in use), and
  `SameSite=Strict`. The cookie's value is a random 256-bit
  nonce; the server keeps the nonce-to-token mapping in memory
  for the lifetime of the process.
- The session cookie is rotated on every successful auth.
- The auth token itself is **never** sent to the browser in
  any response body or header after `POST /login` succeeds.

A loopback bind does not generate a session token; the server
simply sets the session cookie on the first dashboard request
and trusts subsequent requests from the same browser.

---

## Request / response shapes

All JSON bodies follow the same conventions as
`contracts/report.md` (snake_case, RFC 3339 UTC, strict
decoder). The shapes reuse the data model: a `GET
/api/v1/findings/{id}` returns the same JSON object that the
`--format=json` report's `findings[]` element would return.

The `POST /api/v1/fixes/{finding_id}/apply` request body is:

```json
{
  "yes": true,
  "no_restart": false,
  "no_backup": false,
  "force": false
}
```

The response is the same as `hostveil fix --format=json`'s
output, with the `FixRecord` row added under
`fix_record`. On error, the response is `{"error":
"<class>", "detail": "<message>"}` with the appropriate HTTP
status code.

---

## HTML templates

The dashboard renders server-side via `html/template`. The
template set is:

- `layout.html.tmpl` — the page chrome, the session token
  banner (only on `/login`).
- `dashboard.html.tmpl` — the main view: scan summary, findings
  list, history sparkline.
- `finding.html.tmpl` — a single finding's detail view, used
  both as a full page and as an HTMX partial for the "expand"
  action.
- `fix_preview.html.tmpl` — the fix preview panel, used as an
  HTMX partial.
- `fix_result.html.tmpl` — the post-apply result panel, used
  as an HTMX partial.
- `login.html.tmpl` — the auth form.

All templates escape user-supplied content (finding title,
description, location) by default. The redaction list from
`contracts/report.md` is applied to every value before it
reaches the template.

---

## Error and edge-case behavior

| Situation | Behavior |
|---|---|
| `--bind` is non-loopback without `--auth-token` | Exit `2` with a clear error. |
| `--bind` is non-loopback with `--no-tls` | Exit `2` with a clear error. |
| `--tls-cert` given without `--tls-key` (or vice versa) | Exit `2` with a clear error. |
| Bind port already in use | Exit `2`, print the conflicting PID when available. |
| Browser sends a request without a valid session cookie to a non-loopback bind | Redirect to `/login`. |
| Browser sends a request with an expired session cookie to a non-loopback bind | Clear the cookie, redirect to `/login` with a one-time "session expired" flash. |
| Loopback bind with `--auth-token` set | Token is still printed but not required. The session cookie is set on first request. |
| "Apply fix" POSTed to a finding with no built-in fix | `400 Bad Request` with `{"error":"no_built_in_fix", "detail":"..."}`. |
| "Apply fix" needs elevation that has not been granted | `409 Conflict` with `{"error":"elevation_required", "detail":"run hostveil scan first"}`. |
| "Apply fix" fails mid-way (partial fix) | `500 Internal Server Error` with the partial-state descriptor; the dashboard shows a "rollback available" button. |
| "Apply fix" on a `--read-only` server | `403 Forbidden` with `{"error":"read_only"}`. |
| AI provider unreachable on `GET /api/v1/ai/explain/{id}` | `200 OK` with `{"response": null, "fallback": "static", "warning": "<reason>"}`; the dashboard renders the static explanation. |
| Server built with `noweb` tag | Stub subcommand prints "built without Web UI" and exits `0`. |
| Long-running connection (HTMX polling) | Server uses chunked transfer; idle connections are closed after 5 minutes. |
| Concurrent dashboard views | Capped at 16 simultaneous sessions in v3.0.0; further requests get `503 Service Unavailable` with a `Retry-After: 5` header. |
| TLS handshake failure on a non-loopback bind | Server logs the failure, continues to serve. The browser shows a cert warning the user must accept or replace. |
