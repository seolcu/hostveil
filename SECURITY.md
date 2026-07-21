# Security policy

## Reporting a vulnerability

Please report security issues **privately** through GitHub's
[private vulnerability reporting](https://github.com/seolcu/hostveil/security/advisories/new)
rather than opening a public issue.

Include whatever you have: what you did, what happened, and what you expected.
A proof of concept helps but is not required — a clear description of the flaw
is enough to start.

You should get an acknowledgement within a week. hostveil is maintained by a
small team rather than a company with an on-call rotation, so please read that
as a good-faith target and not a guarantee.

## Supported versions

Only the latest release gets fixes. hostveil is a single self-updating binary
with no long-term support branches; if you are behind, upgrade first and check
whether the issue still reproduces.

## What is in scope

hostveil runs as root on the machine it is auditing, so the interesting
questions are about what it does with that privilege:

- **A fix that damages a host.** Any input that makes an applied fix corrupt a
  config file, write outside its declared path, or leave the file in a state
  the checkpoint cannot restore.
- **A fix that cannot be rolled back.** Apply order is backup → write →
  checkpoint, and `applyEdit` refuses to write if the backup fails. A path
  around that ordering is a vulnerability even if nothing is corrupted, because
  reversibility is the promise the whole tool rests on.
- **Command injection through scanned data.** Exec actions carry argv lists and
  never a shell string. A container name, image tag, file path, or config value
  that escapes into a command is in scope.
- **Web dashboard escapes.** `internal/ui/web` binds to loopback and enforces a
  Host allowlist (DNS-rebinding defense) plus same-origin checks on mutating
  requests. Reaching it from another origin, or from a page in the user's
  browser, is in scope.
- **Leaking what it reads.** hostveil reads `/etc/shadow`, SSH keys, and
  compose files containing secrets. Any path that writes those somewhere
  world-readable, into a scan report, or off the host is in scope.
- **Privilege escalation via auto-elevation.** `cmd/hostveil/elevate.go`
  re-execs under sudo. Anything that redirects that to a binary the user did
  not intend is in scope.

## What is not in scope

- **Findings hostveil misses, or reports wrongly.** Detection gaps and false
  positives are real bugs and we want them — but as public issues, not private
  advisories. They do not put anyone at risk by being discussed openly.
- **The severity or score assigned to a finding.** That is a judgement call.
  Argue with it in an issue.
- **Vulnerabilities in the software hostveil audits.** If Docker or OpenSSH has
  a flaw, report it to them.
- **Anything requiring an attacker who already has root on the host.** At that
  point hostveil is not the weakest link.

## Supply chain

Releases are built by GitHub Actions from a tag on `main` and carry checksums,
SBOMs, and a provenance attestation. `scripts/install.sh` verifies the
published checksum before installing.

If you believe a published artifact does not match the source it claims to be
built from, that is in scope and worth reporting privately.
