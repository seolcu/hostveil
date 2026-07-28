# Changelog

## [3.7.0](https://github.com/seolcu/hostveil/compare/v3.6.0...v3.7.0) (2026-07-28)

3.6.0 widened what hostveil looks at. This release is mostly about the gap
between what the engine already knew and what the interfaces would say — and
it turned out to be wider than expected, because 3.6.0 itself shipped through
it. The dashboard mirrored `model.Source` as a hand-written JavaScript object
and the copy stopped at nine entries, so the tenth domain that release added
had no filter chip and announced its own failures as `! 10 failed`. README
advertised eight of the ten domains, missing the two newest. The engine had
emitted per-domain scan progress since the CLI display was built for it, and
the TUI threw every event away. `RollbackForce` had existed for releases and
was reachable from neither UI. Thirty scan snapshots had been kept and pruned
since the store was written and nobody ever read more than the newest one.

None of that was a broken feature. Each was a thing the engine did correctly
and an interface never asked about, which is the failure mode the "one engine,
three thin UIs" rule exists to prevent and which import-checking alone cannot
see. So the fixes come with the guards: the domain table is now generated from
`model.AllSources` the way the palettes are generated from the theme registry,
and README, the docs tables, the CLI reference, and the register of
deliberately-unfixed findings are each pinned to the code they describe.

Those guards started working immediately. Three of the changes below were
caught by a test added earlier in the same cycle before a human looked at
them — a new finding could not reach main undocumented, a fix registered for
a domain could not land without the docs saying so, and a new flag could not
ship without the CLI reference listing it.

**Your score will move on two kinds of host, without your configuration having
changed.** A firewall that is running with a default-allow inbound policy is
now flagged: ufw and firewalld were accepted on the strength of being active,
while nftables and iptables always had to show a default-deny policy, so
hostveil held a hand-written ruleset to a stricter standard than the two
managed front-ends. And the eight kernel-hardening findings move from Manual
to Review, which changes the button they carry, not the number.

### Features

* **fix:** make the kernel-hardening domain fixable
  ([#600](https://github.com/seolcu/hostveil/issues/600)). `sysctl` was the
  only domain with no registered fix at all — eight findings, every one
  Manual, an axis a user could see and not act on. The blocker was recorded
  in the register: persisting a kernel parameter means writing an
  `/etc/sysctl.d` drop-in that does not exist, and edit actions could only
  modify a file already on disk. `Action.CreateIfMissing` removes it, and
  what that reveals is two independent alternatives that were there all
  along — write the drop-in (persistent, effective at the next boot) or
  `sysctl -w` (effective now, gone at the next boot). Neither dominates,
  which is what makes it a choice rather than the sequence Review forbids.
  The delicate half is the undo: restoring "this file did not exist" means
  deleting it, so the checkpoint says so explicitly rather than inferring it
  from an empty backup, the deletion runs behind the same external-edit check
  every other restore gets, and a drop-in the operator has since tuned
  declines instead of vanishing.
* **check:** flag a firewall that runs but accepts everything
  ([#601](https://github.com/seolcu/hostveil/issues/601)). `ufw enable` after
  `ufw default allow incoming` scored the Host firewall axis a perfect 100
  while the host accepted every inbound packet — the same posture that scores
  0 through `firewall.inactive` when nftables is the tool in use. A firewall
  that is running and permitting is not a firewall; it is a log, and the only
  thing it reliably does is make the host look protected. No fix is
  registered: the new policy takes effect on every connection no rule already
  allows, including the SSH session the operator is issuing it from.
* **ui:** let the TUI and dashboard reach two engine features they could not
  ([#602](https://github.com/seolcu/hostveil/issues/602)). The TUI now names
  the domains still working while a scan runs — a screen that cannot
  distinguish "still working" from "hung" is the one place progress is not
  decoration, and on a host with many images that wait is minutes. And a
  declined rollback is now a question in both interfaces rather than a dead
  end: the file changed after hostveil wrote it, restoring the backup would
  discard whatever was done in between, and rollback keeps no checkpoint of
  its own. Only an explicit `y` overrides it.
* **cmd:** show how the score has moved
  ([#603](https://github.com/seolcu/hostveil/issues/603)). `hostveil history
  --scans` reads the snapshots hostveil has been keeping and pruning all
  along. A scan where no domain could be examined shows N/A rather than a
  number, and no change is reported against it — a run nobody could score is
  not a drop to zero.
* **ui:** draw the score trend in the TUI and the dashboard
  ([#606](https://github.com/seolcu/hostveil/issues/606)). The other half of
  the change above, and the same omission this release is otherwise about:
  the engine gained the series and neither interface asked for it. The TUI
  draws it on the history screen, where the checkpoint list already says what
  was changed and the trend says whether it helped; the dashboard draws it
  beside the delta line. `model.Sparkline` buckets the scores once and both
  interfaces render what it returns, so the rule cannot drift the way the
  severity palette and the domain table each did before it.

### Bug Fixes

* **web:** serve the domain table instead of copying it into app.js
  ([#595](https://github.com/seolcu/hostveil/issues/595)). The dashboard
  turned a finding's numeric source into a filter chip through a table
  written out by hand in JavaScript, and when the kernel-hardening domain
  landed in 3.6.0 the copy did not grow a tenth entry. Both consequences were
  silent: the chip list discarded sources it could not name, so eight
  findings became unfilterable, and a failed domain rendered as the raw
  integer. The table now comes from `model.AllSources`, served the way the
  palettes are.
* **history:** write scan snapshots atomically
  ([#597](https://github.com/seolcu/hostveil/issues/597)). The one write in
  the recovery layer that was not atomic, and it landed on the file the next
  scan's delta depends on. A snapshot torn by a crash does not degrade the
  delta, it destroys it.
* **cmd:** stop three commands accepting flags they ignore
  ([#598](https://github.com/seolcu/hostveil/issues/598)). `hostveil history
  --json` printed the human table and exited 0; `fix --all --action 1` looked
  like it had chosen an alternative and had not. Silently accepting a flag is
  worse than rejecting it, because the user believes it did something.
* **fix:** close the gap between Manual by decision and Manual by omission
  ([#599](https://github.com/seolcu/hostveil/issues/599)). Five findings had
  no fix and no recorded reason for not having one, which renders identically
  to a maintainer having weighed the remediation and refused it. Every
  finding now either has a fix or is named in the register with its reason,
  and a test asserts there is no third state.
* **docs:** document all ten domains and pin the tables to the code
  ([#596](https://github.com/seolcu/hostveil/issues/596)). README advertised
  eight of ten — the two missing being AI agent runtimes and kernel
  hardening, the newest and therefore the worst pair to omit from the first
  thing a visitor reads. The CLI reference also contradicted its own
  exit-code table.
* **build:** ship `.deb` and `.rpm` packages
  ([#604](https://github.com/seolcu/hostveil/issues/604)). The only supported
  install path was piping a script into a shell, which is the habit a
  security tool should least be teaching. Docker is *recommended*, never
  required, and removing the package leaves the checkpoint directory alone.

## [3.6.0](https://github.com/seolcu/hostveil/compare/v3.5.0...v3.6.0) (2026-07-28)

3.5.0 asked what happens when something goes wrong. This release goes back to
the day job: seeing more, and putting the results where they can do work. It
widens detection on three fronts — container namespaces, the SSH config, and a
kernel-hardening domain that did not exist — and then gives the report an exit
into CI (SARIF), a way to scope a scan, and the two interface features users
hit the absence of first: a rescan you can watch, and the AI explanation that
only the CLI had.

**Your score will move without your configuration having changed.** A new
domain means new axis weights: Kernel hardening enters at 5, funded by one
point each from container, ssh, cve, firewall, and accounts. And the new
findings — a writable root filesystem in every compose service that lacks
`read_only`, sshd's own 120-second login grace default, eight sysctl values —
fire on configurations that scored clean last week. Nothing got worse on your
host; hostveil is looking at more of it.

### Features

* **check:** audit shared pid/ipc namespaces and writable root filesystems in
  compose services ([#584](https://github.com/seolcu/hostveil/issues/584)). The
  parser has carried `pid`, `ipc`, and `read_only` for a long time; no rule
  read them. `pid: host` lets a compromised container read every host
  process's command line and environment, `ipc: host` hands it the host's
  shared memory, and a writable root filesystem lets it rewrite its own
  binaries. All three are Manual on purpose: the first two are settings nobody
  types by accident, and hostveil cannot tell a monitoring agent's deliberate
  `pid: host` from a cargo-culted one — deleting the line breaks the
  legitimate case silently. Containers started with `docker run` are audited
  too, and a `--read-only` container is not accused of a writable rootfs.
* **check:** extend the sshd audit with grace time, gateway ports, host-based
  and keyboard-interactive auth
  ([#585](https://github.com/seolcu/hostveil/issues/585)). The most honest of
  the four is `ssh.kbdinteractive`, which fires only on a contradiction: you
  set `PasswordAuthentication no`, but keyboard-interactive is still on, and
  on most systems it asks PAM for the very same password — the brute-force
  protection you configured is not actually in force. It respects the pre-8.7
  `ChallengeResponseAuthentication` alias in both directions, because sshd
  keeps the first value it sees for either keyword and a fix that writes the
  losing one would claim to have fixed something while changing nothing.
  `LoginGraceTime` fires on sshd's own 120-second default, deliberately, and
  its fix is Auto because shortening the window cannot lock anyone out.
  `AllowTcpForwarding` is deliberately not audited: hostveil's own remediation
  text tells you to reach admin panels over SSH tunnels.
* **check:** add a kernel/sysctl hardening domain
  ([#587](https://github.com/seolcu/hostveil/issues/587)). A tenth checker
  reading `/proc/sys` directly — no `sysctl` binary needed — for eight
  parameters whose safe value is the same on essentially every server: the
  quiet knobs that stop a local foothold from becoming root and a spoofed
  packet from becoming a route. A knob this kernel does not have is silently
  fine; one that exists but cannot be read degrades the axis rather than
  passing for clean. `net.ipv4.ip_forward` is deliberately absent — Docker,
  WireGuard, Tailscale exit nodes, and virtualization hosts all legitimately
  enable it, and a rule that accuses most self-hosters' routers erodes trust
  in the whole domain. Every finding is Manual for now and carries the exact
  `/etc/sysctl.d` line and `sysctl --system` command, because an edit fix
  cannot create the drop-in file that does not exist yet.
* **check:** recognize Webmin and Proxmox in the exposed-admin-port table
  ([#586](https://github.com/seolcu/hostveil/issues/586)). Two additions with
  unambiguous default ports; Cockpit's 9090 stays out because Prometheus
  claims the same port, and an admin finding titled with the wrong product
  half the time teaches the user to distrust the domain.
* **cmd:** add SARIF output and `--output` to scan
  ([#588](https://github.com/seolcu/hostveil/issues/588)). `--sarif` emits
  SARIF 2.1.0 — the format CI systems and GitHub code scanning ingest — with
  one rule per finding ID, a stable fingerprint per finding so a consumer can
  track it across scans, and the score and per-domain coverage riding in the
  run's properties: a SARIF file with zero results from a scan that could not
  look would otherwise read as a clean host, the exact lie the score model
  refuses to tell. `--output FILE` writes whichever format was chosen, and the
  exit status (0/1/3) does not vary by format or destination — the CI contract
  is the exit code.
* **core:** domain selection for scan (`--only`/`--skip`)
  ([#589](https://github.com/seolcu/hostveil/issues/589)). `--only
  ssh,firewall` runs two checkers instead of ten; the domains that did not run
  report N/A, never 100. A partial scan is not saved as the last-scan baseline
  and produces no delta — saving it would make the next full scan announce
  every finding from the skipped domains as newly appeared, and would
  overwrite the last complete report on disk. A typo in a domain name is a
  usage error naming the valid choices, not a silently empty scan.
* **web:** live rescan progress in the dashboard
  ([#590](https://github.com/seolcu/hostveil/issues/590)). Rescan was a
  blocking POST that took minutes on a real host and gave the browser nothing
  to render but a frozen button. It now returns immediately and the page polls
  a status route, narrating which domains are still working. A second rescan
  while one runs is refused rather than queued, and a closed tab does not
  abort the scan — but Ctrl-C on the server still does.
* **web:** add AI explanations to the dashboard
  ([#591](https://github.com/seolcu/hostveil/issues/591)). The finding panel's
  *Explain with AI* button asks the same local Ollama provider `explain --ai`
  uses, through a token-gated route like every other. With no model reachable
  it renders a one-line note, never an error — AI stays advisory everywhere,
  or it is a dependency, and it must not be a dependency.
* **tui:** add AI explanations to the detail view
  ([#592](https://github.com/seolcu/hostveil/issues/592)). Press `e` in a
  finding's detail. The answer is fetched without blocking the interface, and
  a slow response for a finding you have already left is dropped rather than
  drawn under whatever is on screen now.

## [3.5.0](https://github.com/seolcu/hostveil/compare/v3.4.0...v3.5.0) (2026-07-28)

The previous releases asked whether the score was telling the truth and whether
the interfaces held up on a real screen. This one asks a harder question: what
happens to hostveil, and to the host it is running on, when something goes
wrong.

The answers were not good. A local unprivileged user could arrange their own
home directory so that `hostveil fix --all` chmod'ed `/etc/passwd` on their
behalf. A Docker daemon that accepted a connection and never answered hung the
entire scan with no way out, because the second Ctrl-C was silently discarded
along with the first. The checkpoint store — the only backup mechanism, the
thing every rollback depends on — wrote non-durably and restored without
checking that what it was about to write over your `sshd_config` was intact.
And a scan whose domains had all failed exited 0, so a CI gate could not tell a
blind scan from a clean host.

None of these were reachable by the existing tests, because all of them are
about the paths taken when something has already failed. So this release also
builds the machinery to catch the next one: every command is now bounded and
traceable, the two commands that change a host went from no test coverage to
being driven end to end, and CI now runs the real binary through
scan → fix → rollback inside a seeded container on every pull request.

**Two changes can move your score without your configuration having changed.**
A compose project whose file cannot be parsed now degrades its domain instead
of being silently dropped, and a scan where no domain ran at all now reports
N/A rather than a perfect 100. Both replace a number that was never earned.

### Features

* **cmd:** trace every command hostveil runs, with `HOSTVEIL_DEBUG=1`
  ([#576](https://github.com/seolcu/hostveil/issues/576)). There was no logging
  facility of any kind, so the entire evidence available for *"it says my
  firewall is inactive, but it isn't"* was a domain's one-line reason string,
  truncated to 200 characters. Every claim hostveil makes about a host comes
  from a command, and now each one is logged to stderr with its duration and
  outcome — including the binary lookups that decide whether a domain runs at
  all. Command *output* is deliberately never logged: `docker inspect` reports
  the resolved environment of every container, so a trace pasted into a bug
  report would routinely be a credential leak. Ships with the operator
  troubleshooting guide the docs never had.
* **install:** add an uninstall path, and verify each release's build
  provenance ([#581](https://github.com/seolcu/hostveil/issues/581)). Nothing
  in the repository told a user how to remove hostveil, and nothing said that
  re-running the installer is how you upgrade. `--uninstall` removes the binary
  and deliberately leaves the state directory alone — those checkpoints are the
  backups of every file hostveil has edited on the host, and uninstalling the
  tool is not a decision to give up the ability to undo its fixes. The
  installer also now checks the signed build provenance attestation the release
  workflow has been minting all along: the checksums file comes from the same
  release as the tarball, so matching it proved only that the download was not
  corrupted in transit.
* **web:** require an access token for the dashboard
  ([#564](https://github.com/seolcu/hostveil/issues/564)). Loopback keeps the
  dashboard off the network but not away from the other accounts on the
  machine, and `serve` auto-elevates — so any local user could `curl` root into
  applying fixes. Every route now requires the one-off token printed in the
  startup URL.
* **ui:** add a brand mark and favicon, and tighten the TUI's axis strip
  ([#565](https://github.com/seolcu/hostveil/issues/565)).

### Bug Fixes

* **check:** stop a local user turning the agent audit against the host
  ([#569](https://github.com/seolcu/hostveil/issues/569)). The agent checker
  reads config files inside other accounts' home directories, as root, and
  emits an Auto chmod fix for the ones whose permissions are loose — following
  symlinks at every step. So any user could point `~/.openclaw/openclaw.json`
  at `/etc/passwd`, collect a genuine finding about *its* mode, and have
  `fix --all` tighten the password database to 0600, breaking logins, `sudo`,
  and every `getpwnam` on the machine. A FIFO in the same place parked the scan
  inside `open(2)` forever; a symlink to `/dev/zero` read without bound. Every
  read and every chmod on an attacker-influenceable path now refuses to follow
  a link, cannot block, and is bounded.
* **core:** bound every command, so one wedged daemon cannot hang a scan
  ([#570](https://github.com/seolcu/hostveil/issues/570)). Only Trivy had a
  timeout. Everything else ran with no deadline at all, and a half-dead Docker
  daemon — one that accepts the connection and never answers — is an ordinary
  failure. The single-flight cache made it worse: one hung command parked every
  checker waiting on the same call, so three domains stopped together and the
  user watched `scanning: container cve firewall` until they killed the
  process.
* **core:** make interrupting hostveil actually stop it
  ([#571](https://github.com/seolcu/hostveil/issues/571)). `signal.NotifyContext`
  consumes one signal and returns, but leaves the handler registered — so every
  signal after the first was diverted from its default disposition and silently
  dropped. `hostveil serve` ignored cancellation entirely, leaving a root-owned
  dashboard that answered neither Ctrl-C nor `systemctl stop` and died only
  when systemd escalated to SIGKILL, mid-fix if that is what it was doing.
  Cancellation was also being acted on where it should not be: closing a
  browser tab mid-rescan cancelled the scan, and the resulting empty report
  replaced the good one *and* became the baseline the next scan compared
  against, which then reported the entire host as newly appeared.
* **history:** make the recovery layer durable, and verify backups before
  restoring them ([#572](https://github.com/seolcu/hostveil/issues/572)). The
  checkpoint store is the only backup mechanism hostveil has, and it was the
  one place not using the atomic writer sitting 200 lines away — no fsync, no
  temp-and-rename. Nothing recorded the hash of the backup itself either, so a
  blob truncated by a crash, or by delayed allocation on XFS or btrfs, was
  restored as-is: an empty `/etc/ssh/sshd_config` written over a working one,
  which is precisely the outcome the whole layer exists to prevent. Rollback's
  own write was non-atomic too, so an interrupted restore destroyed the file it
  was restoring. A checkpoint whose metadata could not be read also vanished
  from `hostveil history` with no message, making an applied fix look like it
  had never happened.
* **core:** verify what a fix writes, and record what it half-did
  ([#575](https://github.com/seolcu/hostveil/issues/575)). Nothing ran
  `sshd -t`, anywhere. "The file was written" and "the service will accept it"
  are different claims, and only the second is worth marking a finding fixed
  for — sshd keeps serving from the config it already loaded, so a broken file
  looks like nothing at all until the next restart, when sshd refuses to start
  and repairing it needs the SSH access it just removed. SSH fixes are now
  validated *before* the live file is touched. Separately, an exec fix that
  changed the host and then failed on a later command left no record at all
  while reporting only that it had failed.
* **check:** close three places where a partial scan reported as complete
  ([#574](https://github.com/seolcu/hostveil/issues/574)). A compose project
  whose file could not be parsed was skipped with a bare `continue` and the
  domain reported Done over the rest — the only place left in the tree that let
  "I couldn't look" pass for "nothing there". `sshd_config` parsing stopped
  silently at any line over 64 KiB, so every directive after it read as unset
  and the compiled-in default won the audit, which for `PermitRootLogin` means
  the verdict depended on which side of that line it sat. And on a minimal
  Fedora or Rocky host, a missing `needs-restarting` made the checker return
  before it ever counted pending security updates.
* **cmd:** stop `scan` exiting 0 when it never actually looked
  ([#573](https://github.com/seolcu/hostveil/issues/573)). The exit code came
  from findings alone, and a failed domain produces none — so an unreachable
  Docker socket silenced the two heaviest axes and the pipeline saw a clean
  run. `scan` now exits **3** when a domain failed outright. A domain skipped
  for a missing dependency, or degraded to partial coverage, still does not
  change the status.
* **model:** stop reporting 100 for a scan that examined nothing
  ([#577](https://github.com/seolcu/hostveil/issues/577)). The per-axis N/A
  flag already stopped a skipped domain scoring full marks, but the same lie
  survived in the aggregate: with every axis excluded there was nothing to
  average over and the arithmetic fell out at a perfect 100. Also bounds the
  diff, which could allocate 784 MiB — enough to OOM the 1 GB VPS this tool is
  aimed at — when a compose file was reflowed by the re-encode fallback and
  `fix --all --yes` never read the preview that would have shown it.
* **tui:** compose every mode through one frame layout
  ([#568](https://github.com/seolcu/hostveil/issues/568)). Each view worked out
  its row budget by counting the newlines of chrome it had already rendered,
  arithmetic that had to be re-derived by hand every time the chrome changed
  and was the direct cause of two separate viewport bugs in the last two
  releases. The chrome is now measured first and the body is told what it may
  use.
* **web:** stop the dashboard scrolling sideways on narrow viewports.
* **cmd:** ask two questions in a row without losing the answer to the second
  ([#579](https://github.com/seolcu/hostveil/issues/579)). Each prompt built a
  fresh buffered reader over stdin, and the first read ahead into a buffer that
  went out of scope with it — so choosing an alternative for a Review fix
  consumed the confirmation too, which then read EOF and declined. Applying a
  Review fix interactively was not possible.

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
