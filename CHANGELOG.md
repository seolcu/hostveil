# Changelog

## [3.4.0](https://github.com/seolcu/hostveil/compare/v3.3.0...v3.4.0) (2026-07-23)

hostveil shipped exactly one look, and its palette was written down twice —
once as lipgloss colors in the TUI, once as CSS custom properties in the
dashboard, each file claiming in a comment to match the other with nothing
enforcing it. This release makes the look selectable and, in doing so, gives
that claim an owner: one registry both interfaces read from, so they cannot
drift apart.

It also corrects the website, which was wrong in two places and silent in
several more. The CLI reference documented a `--no-color` flag on `fix` that
does not exist — copying it gets you exit 2 — and described `rollback` as
taking no flags months after `--force` was added, leaving the flag that stands
between an operator and an unrecoverable overwrite of their own edits
documented nowhere at all, not even in `hostveil help`. Both are fixed, and a
test now reads the flag registrations out of the source and fails the build if
the reference and the binary disagree in either direction. Three shipped
features that had never been documented — rollback declining over later edits,
the Skipped/Partial/Failed coverage states, and the dashboard's overview pane —
now are, along with the TUI's key bindings, which had been documented nowhere.
Both screenshots were regenerated: they predated the History button and the
keys the new key table lists.

### Features

* **ui:** add selectable color themes to the TUI and dashboard
  ([#561](https://github.com/seolcu/hostveil/issues/561)). Five themes —
  Instrument (the unchanged default), Gruvbox Dark, Nord, Catppuccin Mocha and
  Tokyo Night — pickable in both interfaces and remembered between runs, or set
  with `--theme` / `HOSTVEIL_THEME`. A theme chosen in the TUI is the one the
  dashboard opens with.

  Ported faithfully, the new palettes were unreadable where it mattered most:
  Nord rendered a Critical finding at 3.05:1 against its own background, and
  four of the five put Low below 3.4:1. Severity is the only thing color
  carries here, so every theme is now held to a floor of 4.5:1 (3.5:1 for Low)
  — not an invented standard, but the one the shipped Instrument palette
  already cleared. Nord's Polar Night ramp is shifted down a step to buy that
  room, which keeps its Aurora orange, yellow and green exactly as published.

## [3.3.0](https://github.com/seolcu/hostveil/compare/v3.2.0...v3.3.0) (2026-07-22)

Where v3.2.0 asked whether the score was telling the truth, this one asks
whether the interfaces reporting it actually hold up on a real screen. Every
change here was found by driving the running software — the dashboard in a
headless browser at phone widths, the TUI through a real terminal — rather
than by reading snapshots of what it renders. All three defects were invisible
to the existing tests, and two of them were invisible to the first version of
the tests written to catch them.

### Features

* **web:** orient the user with an overview in the detail pane
  ([#558](https://github.com/seolcu/hostveil/issues/558)). Half of the first
  screen every user sees read *"Select a finding to inspect it."* and stayed
  that way until they clicked something. It now reads the scan already in
  memory: a verdict in words, the severity mix, the one action that needs no
  per-finding decision, and the most severe findings as a jump list.

### Bug Fixes

* **ui:** keep the TUI frame and the dashboard inside the viewport
  ([#557](https://github.com/seolcu/hostveil/issues/557)). Below about 560px
  the dashboard's status bar pushed History, Rescan and Fix-all-safe clean off
  the right edge — every action the dashboard offers, unreachable unless you
  thought to scroll sideways. The TUI overflowed its own frame on narrow and
  short terminals through four separate unbudgeted widths.
* **tui:** wrap the fix-preview warning and measure history's header
  ([#559](https://github.com/seolcu/hostveil/issues/559)). The warning that a
  fix has no rollback rendered as one unwrapped line, so on a narrow terminal
  it was clipped mid-sentence — cutting off, among other things, the words
  "there is no rollback".

## [3.2.0](https://github.com/seolcu/hostveil/compare/v3.1.0...v3.2.0) (2026-07-22)

This release is mostly about a single question: was the score telling the
truth? On the kind of host hostveil is built for — a VPS running Docker
behind ufw — several axes were scoring configurations they could not
actually see, so a host could look clean while a datastore was open to the
internet. Measured on the demo VM, three of those axes moved: firewall
100 → 50, containers 100 → 15, auto-updates 88 → 60, all on the same
unchanged host.

**Your score will probably drop after upgrading, without your configuration
having changed.** That is the point of this release.

### Features

* **check:** flag container ports that bypass an active ufw firewall
  ([#546](https://github.com/seolcu/hostveil/issues/546)). Docker writes its
  rules ahead of ufw's, so `ufw deny 6379` does nothing to a container
  published with `-p 6379:6379`. hostveil previously *rewarded* this: an
  active ufw scored full marks and suppressed the exposed-ports finding.
* **check:** audit containers started outside Compose
  ([#548](https://github.com/seolcu/hostveil/issues/548)). Both the container
  and CVE checkers enumerated only through `docker compose ls`, so a
  hand-started `docker run` container — often the most dangerous thing on the
  box — was invisible to 31 points' worth of scoring.
* **check:** report pending security updates and a required reboot
  ([#547](https://github.com/seolcu/hostveil/issues/547)). Having
  unattended-upgrades enabled was the whole check, so a host with 60 pending
  patches and an installed kernel update it had never rebooted for scored
  full marks.
* **ui:** tell the user what to do after a scan
  ([#550](https://github.com/seolcu/hostveil/issues/550)). The report labelled
  findings Auto/Review/Manual without ever naming the command that acts on one.
* **ui:** show what changed since the last scan in the TUI and dashboard
  ([#541](https://github.com/seolcu/hostveil/issues/541)).
* **history:** refuse to roll back over edits made after the fix
  ([#554](https://github.com/seolcu/hostveil/issues/554)). Rollback overwrote
  whatever was on disk with no checks at all, and keeps no backup of its own —
  so hand-editing a file after fixing it and then rolling back destroyed that
  work irrecoverably. Use `--force` to restore anyway.

### Bug Fixes

* **check:** follow `sshd_config` `Include` directives
  ([#539](https://github.com/seolcu/hostveil/issues/539)). Debian and Ubuntu
  put the `Include` at the top of the file and sshd keeps the first value it
  finds, so drop-ins win — meaning findings could be reported from a file sshd
  was not using, and fixes could edit the wrong one.
* **check:** detect firewalld by exit status, and recognise iptables-only hosts
  ([#545](https://github.com/seolcu/hostveil/issues/545)). Both defects
  accused a firewalled host of having no firewall.
* **check:** skip hosts whose automatic updates cannot be verified
  ([#540](https://github.com/seolcu/hostveil/issues/540)). Alpine, Arch and
  openSUSE scored the updates axis 100 for a check that never ran.
* **core:** show newline-only changes and elide distant context in fix previews
  ([#542](https://github.com/seolcu/hostveil/issues/542)). A change to the
  trailing newline was invisible in the preview, so preview and write
  disagreed.
* **cmd:** stop dropping flags on a terminal and exiting 2 on `--help`
  ([#549](https://github.com/seolcu/hostveil/issues/549)). `hostveil --json`
  opened the TUI and discarded the flag when run on a terminal, while working
  correctly when piped.
* **history:** give scan snapshots unique IDs, and test the ordering for real
  ([#553](https://github.com/seolcu/hostveil/issues/553)). Two scans in the
  same millisecond overwrote each other, and the test named for the history
  ordering was passing vacuously.

### Documentation and infrastructure

* `SECURITY.md` and `CONTRIBUTING.md`
  ([#552](https://github.com/seolcu/hostveil/issues/552)); vulnerabilities can
  now be reported privately.
* CI checks hostveil's own dependencies with govulncheck
  ([#551](https://github.com/seolcu/hostveil/issues/551)).
* Releases are cut by hand rather than through release-please
  ([#555](https://github.com/seolcu/hostveil/issues/555)), which could never
  satisfy the branch ruleset it was merged under.

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
