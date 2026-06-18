# Hostveil v3.0.0

A single-binary Linux tool that scans a self-hoster's host for common
security misconfigurations across six categories (SSH, Docker, image
CVEs, reverse proxy, SSL/TLS, and system hardening), presents the
findings in plain language, and applies reversible fixes with a
built-in rollback path. v3 ships three user surfaces — a CLI, an
interactive TUI, and a local web dashboard — plus an opt-in AI layer
for richer explanations.

> v3 is a full rewrite from the previous v2.5.2 implementation. The
> v2.5.2 codebase is intentionally not present in this repository and
> MUST NOT be referenced when making v3 design or implementation
> decisions.

## Install

```bash
# From a release tarball
curl -L -o /tmp/hostveil.tgz \
  https://github.com/seolcu/hostveil/releases/download/v3.0.0/hostveil_3.0.0_linux_amd64.tar.gz
tar -xzf /tmp/hostveil.tgz -C /tmp
sudo install -m 0755 /tmp/hostveil /usr/local/bin/hostveil
hostveil version
```

See [specs/001-selfhost-security/quickstart.md](specs/001-selfhost-security/quickstart.md)
for the five-minute tour, the TUI tour, the web UI tour, and the AI
tour. The full design lives in
[specs/001-selfhost-security/plan.md](specs/001-selfhost-security/plan.md).

## Surfaces

| Surface | Invocation | Notes |
|---|---|---|
| CLI | `hostveil scan` | the canonical entry point |
| TUI | `hostveil tui` | keyboard-driven, requires a TTY |
| Web | `hostveil web` | localhost dashboard (HTTPS when bound to a non-loopback address) |
| AI | `hostveil ai explain ...` | opt-in per call; defaults to local Ollama |

## Build

```bash
make build          # default binary
make build-noai     # excludes all AI code
make build-notui    # excludes the TUI
make build-noweb    # excludes the web UI
make build-cross    # cross-compile to linux/{amd64,arm64,386,arm/v7}
```

## License

MIT. See [LICENSE](LICENSE).
