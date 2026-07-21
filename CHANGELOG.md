# Changelog

## [3.2.0](https://github.com/seolcu/hostveil/compare/v3.1.0...v3.2.0) (2026-07-21)


### Features

* **check:** audit containers started outside Compose ([#548](https://github.com/seolcu/hostveil/issues/548)) ([7d85904](https://github.com/seolcu/hostveil/commit/7d85904f3b2d51d93a06b4d62e0b588e2e11367e))
* **check:** flag container ports that bypass an active ufw firewall ([#546](https://github.com/seolcu/hostveil/issues/546)) ([32d0ace](https://github.com/seolcu/hostveil/commit/32d0aced72cf988047ff8c64805f96aff93dc156))
* **check:** report pending security updates and a required reboot ([#547](https://github.com/seolcu/hostveil/issues/547)) ([e46d1de](https://github.com/seolcu/hostveil/commit/e46d1debedb12d5260b297d02f73a28f2436a473))
* **history:** refuse to roll back over edits made after the fix ([#554](https://github.com/seolcu/hostveil/issues/554)) ([8d44bf8](https://github.com/seolcu/hostveil/commit/8d44bf884411659bde38ea3ffee1c1bfe8289289))
* **ui:** show what changed since the last scan in the TUI and dashboard ([#541](https://github.com/seolcu/hostveil/issues/541)) ([bdc3dd8](https://github.com/seolcu/hostveil/commit/bdc3dd80315f04ddd1c9e11a457918c93d598437))
* **ui:** tell the user what to do after a scan ([#550](https://github.com/seolcu/hostveil/issues/550)) ([c7e2f45](https://github.com/seolcu/hostveil/commit/c7e2f45a0af050bcdb5ddaef0218e288c3e67e13))


### Bug Fixes

* **check:** detect firewalld by exit status and recognize iptables-only hosts ([#545](https://github.com/seolcu/hostveil/issues/545)) ([7af73ec](https://github.com/seolcu/hostveil/commit/7af73ec2aa30ad9e36f022a84b9f99d86166f230))
* **check:** follow sshd_config Include directives when parsing SSH config ([#539](https://github.com/seolcu/hostveil/issues/539)) ([e00b5f0](https://github.com/seolcu/hostveil/commit/e00b5f0fb9a45bf6742147a4b6a60c1a4b0da497))
* **check:** skip hosts whose automatic updates cannot be verified ([#540](https://github.com/seolcu/hostveil/issues/540)) ([028f4f2](https://github.com/seolcu/hostveil/commit/028f4f2f92716bedbe1d63066424e9ceca5d053d))
* **cmd:** stop dropping flags on a terminal and exiting 2 on --help ([#549](https://github.com/seolcu/hostveil/issues/549)) ([f55f4ed](https://github.com/seolcu/hostveil/commit/f55f4ed732622468e9b7e5d5e0ebeec2080bf751))
* **core:** show newline-only changes and elide distant context in fix previews ([#542](https://github.com/seolcu/hostveil/issues/542)) ([f2beb43](https://github.com/seolcu/hostveil/commit/f2beb43d44fd2e35494ecdf8a0f315389bbe8142))
* **history:** give scan snapshots unique IDs and test the ordering for real ([#553](https://github.com/seolcu/hostveil/issues/553)) ([1cef986](https://github.com/seolcu/hostveil/commit/1cef9869a2ca036388a33bd166ae9f0e6195111b))

## [3.1.0](https://github.com/seolcu/hostveil/compare/v3.0.0...v3.1.0) (2026-07-20)

This is the first release cut from `main` since v2.6.0, and the first produced
by the automated release pipeline. The `v3.0.0` tag was published from a
rewrite branch that never merged, so this release — not that one — is what the
v3 line actually is.

The sections below were generated from conventional-commit history, which for
this window covers only part of the work: the rewrite landed under `P0:`–`P8:`
prefixes that carry no commit type, so it is summarised here by hand. Later
releases will not need this note — pull request titles are linted now, and
merges to `main` are squashed, so the generated sections are the whole story
from here on.

### Highlights

* **Rewritten around a single engine.** `internal/core.Engine` owns scanning,
  scoring, classification, preview, apply, and rollback; the CLI, TUI, and web
  dashboard are rendering layers over it, enforced by tests that fail if UI
  code reaches past it. A fix applied in any of the three behaves identically
  and is reversible from any of them.
* **New detection domains** beyond containers and SSH: open ports, user
  accounts, file permissions, and self-hosted AI agent runtimes.
* **CVEs are reported per image**, with a rollup finding you can act on,
  instead of one finding per CVE.
* **Scoring no longer bottoms out.** Findings erode an axis multiplicatively
  rather than summing into a clamp, so a host with 27 container findings no
  longer scores the same as one with 3.
* **A scan that could not look no longer reports a clean result.** Partial
  coverage is representable and surfaced as a degraded axis, closing the path
  by which a non-root scan once reported a perfect CVE score.
* **Rollback from every surface** — a history screen in the TUI and reversible
  applied fixes in the web dashboard.
* **Compose fixes render as minimal text edits** rather than a whole-file
  re-encode, so a one-line change stays a one-line diff.
* **Auto-elevation**: commands that benefit from root re-exec under sudo
  instead of failing.
* **Website generated from a single source** (`cmd/sitegen`), with a docs site,
  client-side search, and a Korean localization.
* **Reproducible demo VM** (Vagrant) for exercising the tool against a
  deliberately vulnerable host.
* **Releases ship an SBOM and build provenance attestation.**

### Features

* add an agent domain for self-hosted AI agent runtimes ([f4ceb90](https://github.com/seolcu/hostveil/commit/f4ceb906e399d28c133e7095395442ba631aa7de))


### Bug Fixes

* define when a fix may be Auto, and stop the registry overruling it ([66f590b](https://github.com/seolcu/hostveil/commit/66f590b7cbdf110d923dd349aa3f521906de272e))
* do not call any interpreter process an agent gateway ([e37455b](https://github.com/seolcu/hostveil/commit/e37455bb749aa6ff0bbb074771e948db839cf078))
* enumerate the registry instead of a hand-kept list ([302713b](https://github.com/seolcu/hostveil/commit/302713beefc311f817942da560474c3c0c4c38b6))
* give fileperms a chmod that can be rolled back ([236b8b7](https://github.com/seolcu/hostveil/commit/236b8b7f651e64f8d173791b7fcb27da6a870152))
* keep type bits when tightening a mode ([4268e20](https://github.com/seolcu/hostveil/commit/4268e20d341d6a57770bbe01dbaa393289bd185c))
* register the CVE image rollup and a memory-limit fix ([06d6beb](https://github.com/seolcu/hostveil/commit/06d6bebcc1fdc1d5c17ca55e0ca79f99e7c6b72e))
