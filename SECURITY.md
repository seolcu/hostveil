# Security Policy

## Threat model

hostveil runs as **root** and produces a snapshot of the host's
Docker Compose projects, system configuration, and container
image CVEs. The two outputs of hostveil that cross a trust
boundary are:

1. **The Web UI**: an embedded HTTP server that exposes the
   snapshot, fix-application endpoints, and fix history. By
   default it binds to `127.0.0.1:8787`, so it is reachable
   only from the local machine.
2. **The exported report**: a JSON or CSV dump of the
   snapshot, written to disk or downloaded via the Web UI.

Both are sensitive: they reveal network services, secrets in
env files, and which system files are misconfigured. Treat them
as you would any other host audit report.

## What hostveil does and does not protect against

### Does

- **CSRF on state-changing endpoints.** `POST /api/fix`,
  `/api/fix/batch`, `/api/rescan`, `/api/recalc`, and
  `/api/export` reject requests whose `Origin` does not match
  the `Host` header. Browsers always send `Origin` on
  cross-origin POSTs, so a malicious site open in another tab
  cannot trigger fix application.
- **Secure response headers.** `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy:
  no-referrer`, `Cache-Control: no-store`, and a tight
  `Content-Security-Policy` are set on every response.
- **Body size cap.** Request bodies are capped at 1 MiB.
- **XSS-safe rendering.** All user-controlled text rendered
  in the Web UI is HTML-escaped at insertion time.
- **TLS support** via `--cert-file` and `--key-file`. Without
  these flags the server is plain HTTP, which is appropriate
  for a localhost-only listener.
- **Port reclaim protection.** If the target port is held by
  another hostveil process, the listener is killed before
  rebinding. If the port is held by a non-hostveil process,
  hostveil refuses to steal it.

### Does not (yet)

- **Authentication.** Anyone who can reach the bound port can
  apply fixes. There is no login. If you bind to `0.0.0.0`,
  every host on the network can apply fixes to the running
  system.
- **Authorization per fix.** Any reachable client can
  request any registered fix.
- **Rate limiting.** A tight loop on `/api/rescan` will spawn
  a new scan each time.

## Reporting a vulnerability

Please open a private security advisory on GitHub
(`https://github.com/seolcu/hostveil/security/advisories/new`)
rather than filing a public issue. Include:

- A description of the vulnerability and the attack scenario.
- Reproduction steps, ideally with a minimal finding payload.
- The hostveil version (output of `hostveil --version`).
- Whether you intend to disclose publicly, and on what
  timeline.

We aim to acknowledge new reports within 3 business days
and to issue a fix or mitigation within 14 days for high-
severity issues. Credit is given to reporters in the release
notes unless they ask to remain anonymous.

## Non-local bind warning

The Web UI prints a one-line warning when the bind address
starts with `0.0.0.0` or `:`. This warning is intentionally
easy to ignore. Binding to a non-local address **exposes your
host scan results and allows remote fix application** to
anyone on the network. Use this only in trusted networks,
ideally behind a reverse proxy with TLS and authentication.

## Reporting hostveil's own vulnerabilities

hostveil is itself a Go program running as root. A compromise
of the binary would give the attacker root on the scanned
host. Standard defenses apply:

- Download from official GitHub releases only.
- Verify the SHA-256 checksum against
  `hostveil-checksums.txt` in the release.
- The installer pins the upstream `install.sh` against its
  own checksum.
- `hostveil update` downloads directly from the GitHub
  release artifacts and re-verifies checksums before
  installing.
