# web

The embedded HTTP server and the static Web UI assets.

## Files

- **`server.go`** — the HTTP server. Endpoints:
  - `GET /api/health`
  - `GET /api/result`
  - `POST /api/fix`
  - `POST /api/fix/batch`
  - `POST /api/rescan`
  - `POST /api/recalc`
  - `GET /api/export?format=json|csv`
  - `GET /` — the embedded static Web UI

  Plus the CSRF / security middleware (`sameOrigin`, `secureHeaders`,
  `hostGuard`) and the port-reclaim logic (`listenWithReclaim`,
  `listenerPIDs`, `listenerPIDsViaLsof`).

- **`hostguard_test.go`** — `allowedHostsFor` and `hostGuard` tests,
  including two that reproduce the exact DNS-rebinding request shape
  (`Origin == Host`, both attacker-controlled) that `sameOrigin` alone
  cannot reject.

- **`assets/`** — the static Web UI. `index.html`, `app.css`,
  `app.js`. Embedded via `//go:embed assets/*`.

- **`server_test.go`** — handler tests. Uses `httptest` for
  unit-level tests and `httptest.NewServer` for end-to-end tests
  of the security middleware and the static asset serving.

## Security model

The Web UI is a localhost-only tool, but it still implements several
defenses in depth:

- **CSRF** — `sameOrigin(origin, host)` rejects state-changing
  requests whose `Origin` does not match the `Host` header.
- **DNS rebinding** — `hostGuard(bindAddr, next)` wraps every route
  (applied once in `Serve()`, not per-handler) and rejects requests
  whose `Host` header doesn't match how the server was actually
  bound. This is a *separate* defense from CSRF: after a DNS rebind,
  an attacker's request has `Origin` and `Host` both reading as the
  attacker's domain, so `sameOrigin` sees them match and would let it
  through. `hostGuard` checks `Host` against a fixed allowlist
  derived from `bindAddr` instead — nothing the client sends can
  affect that allowlist. See `allowedHostsFor` for the exact rules
  (loopback binds accept `127.0.0.1`/`::1`/`localhost`; a specific
  non-loopback bind is exact-match only; a wildcard bind skips the
  check since the operator already opted into broader exposure).
- **Secure headers** — `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`, and a tight `Content-Security-Policy`.
- **Body cap** — `http.MaxBytesReader(w, r.Body, 1<<20)` (1 MiB).
- **Port reclaim** — only reclaims the port from another hostveil
  process. Refuses to steal from any other process.
- **Bind warning** — emits a one-line warning when the bind
  address starts with `0.0.0.0` or `:` (skipped under
  `HOSTVEIL_TEST=1` so tests are not noisy).

See `SECURITY.md` for the full threat model.

## XSS surface

The frontend has no build step. `app.js` is hand-written
ES2020+ that builds DOM with template strings. Every value
rendered into `innerHTML` must be HTML-escaped with
`escapeHTML(...)`. Browser-decoded `data-*` attribute values
must be re-escaped on read, since the browser has already done
entity-decoding once.

The `xss.spec.ts` Playwright test is a regression test for the
XSS surface in the detail panel and the collapsible section.
