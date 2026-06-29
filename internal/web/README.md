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

  Plus the CSRF / security middleware (`sameOrigin`, `secureHeaders`)
  and the port-reclaim logic (`listenWithReclaim`,
  `listenerPIDs`, `listenerPIDsViaLsof`).

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
