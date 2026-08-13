# Changelog

## [3.18.0](https://github.com/seolcu/hostveil/compare/v3.17.0...v3.18.0) (2026-08-14)

Installing hostveil took one command and updating it took the whole URL again.
This release closes that: `hostveil update` and `hostveil uninstall` act through
whichever tool put the binary there, and a scan says once a day when a newer
release exists.

The update path was written, then run, and running it is what found the four
bugs listed under Bug Fixes. Every one of them was silent.

### Features

* **cmd:** `hostveil update` and `hostveil uninstall`
  ([#726](https://github.com/seolcu/hostveil/issues/726)). Each works out how
  this binary was installed and acts the same way: the install script's binary
  is replaced in place, a `.deb` is updated with the release's own `.deb`
  through `apt-get` so dpkg keeps describing the filesystem correctly, an
  `.rpm` the same through `dnf`, and a `go install` binary is rebuilt from
  source rather than overwritten with somebody else's build. Only an origin
  hostveil cannot identify falls back to printing advice, because guessing
  there means overwriting a file another tool believes it owns.

  Verification is a gate rather than a warning. The download is checked against
  the release's checksums file and discarded if it does not match, and where
  the GitHub CLI is present the signed build provenance is verified too. A
  provenance check that fails stops the update; one that cannot run because
  `gh` is not installed is a note, since a checksum proves the bytes arrived
  intact and nothing about who produced them.

  Uninstalling leaves the saved scans and rollback checkpoints alone and prints
  where they are before it asks rather than after. Those are the backups of
  every file hostveil edited on that host.

* **cmd:** a once-a-day update check, notice only
  ([#726](https://github.com/seolcu/hostveil/issues/726)). A scan, the
  dashboard and the TUI each refresh a cached answer in the background and
  print one line when a newer release exists. Nothing waits for the request,
  nothing is installed, and a check that fails says nothing: a host behind a
  proxy does not have a problem hostveil should be reporting under a security
  scan. The line appears in human output only, never in `--json`, SARIF, or a
  report written to a file. `HOSTVEIL_NO_UPDATE_CHECK=1` stops it contacting
  GitHub at all.

### Bug Fixes

* **release:** the `.deb` and `.rpm` archives now carry a provenance
  attestation ([#726](https://github.com/seolcu/hostveil/issues/726)). They
  were left out of `subject-path`, so a packaged host's own update refused its
  provenance check and stopped.

* **cmd:** `update --check` no longer asks for a password
  ([#726](https://github.com/seolcu/hostveil/issues/726)). It makes one request
  and writes nothing. It is the one command whose need for root depends on its
  flags, and the guard test that would have caught this was rewritten to state
  the real rule rather than the shape it had assumed.

* **cmd:** an update on a current host is no longer offered forever
  ([#726](https://github.com/seolcu/hostveil/issues/726)). goreleaser stamps
  `v3.17.0` and the release tag is trimmed to `3.17.0` to build an asset URL,
  so the two never compared equal.

* **cmd:** an install that changed nothing is no longer reported as success
  ([#726](https://github.com/seolcu/hostveil/issues/726)). `apt-get install` on
  a version dpkg already records exits 0 having done nothing, and so does a
  `go install` that resolves to a cached build. hostveil now asks the binary
  its version afterwards.

### Documentation

* The rules behind every judgement are published
  ([#724](https://github.com/seolcu/hostveil/issues/724)). Most of them already
  were, so this fills what was actually missing, in the pages it belongs to.
  The score bands and their wording, which appeared nowhere even though every
  interface says "This host is wide open"; the `pending` verification result,
  which the fixing page was the only one of five to omit; that index 0 is the
  recommended alternative and what "recommended" means for an unattended batch;
  the shape rule that makes the four-step classification procedure something a
  reader can apply themselves; the SARIF level and `security-severity` mapping,
  including why a hostveil High lands in GitHub's *critical* band on purpose;
  checkpoint retention; and what counts as a port exposed on all interfaces.
  The README is aligned with the site, which called the same kind two different
  things. Each transcribed constant is pinned to its source, and the SARIF one
  reads the values out of a real export rather than a second list.

  Em dash density was measured against published guidance on machine-written
  prose and was the one marker the docs actually carried: 12.4 per thousand
  words in English, 13.5 in Korean, against a ceiling of about one. The two
  worst pages are cleared in both languages and nothing written here uses any.

## [3.17.0](https://github.com/seolcu/hostveil/compare/v3.16.0...v3.17.0) (2026-08-14)

The release where hostveil stopped saying things about the host that were not
true. Three fixes were reporting success over a machine nothing had changed
about, a fourth was applying the opposite of its own advice, and the test suite
could not have told you about any of it — because nothing in it had ever fed a
real fix's output back to the real checker.

That instrument exists now, and it is what found the rest.

### Features

* **tui:** the scan screen draws what the model already knew
  ([#712](https://github.com/seolcu/hostveil/issues/712)). One dim line in an
  empty frame became a row per domain, a bar, and the elapsed time. The
  progress was already on the model; the denominator had to come from the
  engine, because a checker announces itself when it *starts* — so a reader of
  the event stream can count what has happened and never what is left.
  Deliberately no estimate of the time remaining: eleven of twelve domains
  finish inside a second and the twelfth shells out to Trivy, so a figure would
  be confidently wrong for most of the wait.

### Bug Fixes

* **compose:** edit the file that decides, or decline and say which ones do not
  ([#718](https://github.com/seolcu/hostveil/issues/718)). The checker asks
  docker for the merged project; the fix edited the *first* file of it. On a
  base+override layout — which `discover.go` itself calls the ordinary case —
  that rewrote one file while the other went on publishing the port on every
  interface, and reported success with a checkpoint. Scalars now resolve
  last-wins; ports are *appended* by compose, so where more than one file
  publishes wide hostveil declines and names them. It also recovers a
  capability that was being lost silently: the common layout failed to build
  and demoted a fixable finding to Manual with no explanation.

* **core:** a re-check of the file a fix wrote is not a re-check of the host
  ([#720](https://github.com/seolcu/hostveil/issues/720)). `verifyFix` re-ran
  the compose checker over the file the compose fix had just edited, found
  nothing, and returned *"Re-checked: the finding is gone"* — while the
  container still published the port. The warning agreed with it. New
  `Action.TakesEffectOn` and `model.VerifyPending` say the file is correct and
  the change reaches the host when the service is recreated.

* **fix:** the first alternative is the recommendation, and one recommended the
  opposite ([#719](https://github.com/seolcu/hostveil/issues/719)).
  `fix --all --review` applies index 0 without asking, and `compose.ds010` led
  with the *smallest* memory limit while the warning beside every alternative
  said to start generous — so it capped every unlimited container at 512m.
  Each Review fix's recommendation is now named in words, including what
  "recommended" means for an unattended batch as against a person.

* **check:** two layered configurations hostveil read one file of
  ([#721](https://github.com/seolcu/hostveil/issues/721)). apt reads every
  fragment in `apt.conf.d` last-wins, and hostveil read `20auto-upgrades`
  alone — as did its fix, so checker and fix shared one wrong oracle and
  confirmed each other. `apt-config dump` decides now. And the firewall fix
  allowed only the *first* sshd listener, severing the second on any host
  mid-port-migration, which is the standard way to change the SSH port without
  locking yourself out.

* **cmd:** ask for the password once the arguments make sense
  ([#716](https://github.com/seolcu/hostveil/issues/716)). Elevation ran before
  dispatch, so `hostveil --no-such-flag` took a password, re-executed as root,
  and *then* exited 2 on a usage error. And when sudo is absent it now says so
  instead of running unprivileged in silence.

* **model:** a degraded axis scoring 100 is four columns, and every renderer
  budgeted three ([#711](https://github.com/seolcu/hostveil/issues/711)). The
  frame clipped the overflow, and what it cut was the `~` — so a partially
  scanned axis read as a clean 100.

* **tui:** the rail reads as pairs, the inline block stops repeating the row
  above it ([#714](https://github.com/seolcu/hostveil/issues/714)), and two
  screens that had the room and not the words
  ([#713](https://github.com/seolcu/hostveil/issues/713)) — the fix preview did
  not name the finding, the kind, or whether it could be undone, while the
  rollback confirmation said all three.

* **web:** tell Firefox what colour the scrollbar is
  ([#715](https://github.com/seolcu/hostveil/issues/715)). `color-scheme: dark`
  was already set and is not enough; measured against a control page, every
  dashboard screenshot this project has taken had a white stripe down it.

### Under it

`internal/fix`'s round-trip test ([#717](https://github.com/seolcu/hostveil/issues/717))
takes a host the real checker flags, applies the real registered fix, and hands
the result back to the same checker. Nothing had ever done that. Its limit is
written into the file too: it uses one oracle at both ends, so it cannot see a
checker reading the wrong artifact — which is the apt bug, found separately.

And the two domains declined *whole* — `dockerd.*` and `systemd.*`, eleven
findings — were re-examined and stay declined, with what changed and what did
not now recorded ([#722](https://github.com/seolcu/hostveil/issues/722)).
Fix coverage is unchanged at 37 of 74 findings. That is the honest number.

## [3.16.0](https://github.com/seolcu/hostveil/compare/v3.15.0...v3.16.0) (2026-08-13)

A release about hostveil telling the truth when something goes wrong. The score
now says what it would become if you accepted every fix on offer, so a number
you cannot move is distinguishable from one you can; and eleven places that
reported a failure as a success, a blind spot as a clean result, or a missing
answer as a negative one have been made to say what actually happened.

One of those was introduced during this cycle and never reached a release: a
refactor's regular expression rewrote prose inside string literals, so every
CVE finding read `The t.image nginx:1.21 ships …`. The full gate passed, and so
did the frame and pixel comparisons offered as evidence that nothing had
changed — because neither one renders a sentence a checker wrote. There is now
a test that reads the prose of all twelve domains.

Behind those: `AGENTS.md`'s headline invariant on apply order was wrong and
contradicted itself six lines later, which matters because the recovery layer's
safety argument rests on it; five invariants that were true and enforced by
nothing are now pinned, each verified by breaking the code and watching the pin
fail; and `gosec` is enabled, having found that twenty existing suppressions and
the linter disagreed about where the risk was.

### Features

* **model:** the score says what it could be
  ([#700](https://github.com/seolcu/hostveil/issues/700)). A score you cannot
  improve by doing everything right measures nothing, and until now the only
  number hostveil showed was the one you have. `ScoreBreakdown.AfterFixes` is
  the same scoring run over the same findings with every Auto and Review fix
  treated as applied, so an operator can tell a 61 that becomes an 88 from a 61
  that stays a 61 because the remaining findings are Manual or have no upstream
  patch. It is computed by calling the existing scorer twice rather than by a
  second model of what a fix is worth, which is what keeps the two numbers
  commensurable.

### Bug Fixes

* **cve:** the prose in five strings
  ([#704](https://github.com/seolcu/hostveil/issues/704)). Restored, and pinned:
  `internal/docs/prose_test.go` walks every string literal under
  `internal/check`, `internal/fix` and `internal/model` through the AST and
  fails on anything shaped like a leaked Go selector. The regex itself is held
  to the four broken sentences and seven safe ones, in both directions.

* **fix:** four failure paths that told the operator the wrong thing
  ([#705](https://github.com/seolcu/hostveil/issues/705)). `fix --all` printed
  `✓` and exited 0 when every fix in the batch failed, so an unattended wrapper
  read a run that changed nothing as a success. A rollback that failed halfway
  restored some files and reported nothing about which — the pre-check exists
  to prevent exactly that state, and the write loop returned at the first
  error anyway; it now accumulates and `RollbackOutcome` names the files that
  did not move. A checkpoint whose write failed stayed on disk claiming, in its
  `AppliedSHA256`, to have written bytes that were never written — permanently
  weakening the external-edit guard on that path. And `ApplyBatch` reported a
  fix that failed to build as `Skipped`, indistinguishable from a finding with
  no fix at all.

* **check:** three places where "I could not look" was reported as an answer
  ([#706](https://github.com/seolcu/hostveil/issues/706)). `updates` read any
  `systemctl` failure — the binary absent, systemd not booted, permission
  denied — as a positive assertion that automatic security updates are off,
  while the reboot check six lines below made that distinction carefully. It
  now asks for `LoadState` and requires `loaded`; the apt path distinguishes an
  absent config, which is a real answer, from an unreadable one, which is not.
  `firewall` discarded its second coverage gap on purpose, which is the failure
  both container checkers were fixed for. And on a `docker run` host, seven
  findings demoted to Manual at runtime arrived with the "why is there no fix
  button" panel empty, because the field that answers that question is
  consulted for unregistered IDs only.

* **tui:** the batch bar promised work the batch key would not do
  ([#701](https://github.com/seolcu/hostveil/issues/701)). It counted Auto
  findings over the unfiltered report while `a` applied over the filtered list,
  so narrowing to one severity offered `fix all 10 safe` and applied three. All
  five places that counted this by hand now go through
  `Report.AutoFixable(Filter)`, and the dashboard's deliberately different
  answer — its chips narrow the list, not the batch — is now deliberate rather
  than accidental. In the same change: the agent checker stopped running four
  firewall binaries per scan whose answer it had not read since the severity
  levels merged, the composer's regression net grew from 8 of 10 modes to all
  of them (the missing two included the screen shown when a rollback is
  declined), and both published screenshots stopped showing a domain as N/A
  with no reason beside it.

## [3.15.0](https://github.com/seolcu/hostveil/compare/v3.14.4...v3.15.0) (2026-08-13)

Three things that had been declined, stale, or impossible for a reason that
stopped being true. The largest scoring gap hostveil had — a domain it could
detect and never fix — is mostly closed; the screenshot on the website has
stopped describing a severity scale that no longer exists; and the measurement
fixture builds a host on more than one distribution.

### Features

* **fix:** OpenClaw's config keys are fixable
  ([#696](https://github.com/seolcu/hostveil/issues/696)). Seven `agent.*`
  findings were declined together for one shared reason: they all reduce to
  editing a key in a JSON5 config carrying the operator's own comments and
  trailing commas, and re-encoding it through `encoding/json` deletes every one
  of them. `internal/json5` is the editor that was missing — built the way
  `internal/compose/edit.go` is, locating the value's bytes and replacing
  exactly those, with the fallback deliberately absent because here a
  re-encode *is* the damage. A rendering it cannot prove correct is an error
  and the fix is not offered.

  Four findings became fixable, and the shape is read off the rule table rather
  than decided in the registry: one safe value is Auto, two are Review.
  `agent.exec-unrestricted` is the Review case — `deny` and `ask` are a choice
  about how the operator wants to work, not a sequence.

  Three stayed declined, and removing the shared reason is what made their real
  ones visible. `agent.sandbox-off`: hostveil knows `off` is wrong and nothing
  in the project names the mode that turns the sandbox on, so any value it
  wrote would be a guess wearing a fix's clothes. `agent.auth-disabled`: the
  safe posture is an *absent* key, which an editor that only replaces values
  cannot produce. `agent.gateway-exposed`: rebinding can cut an operator off
  from the agent they administer remotely.

  These are also the first edits aimed inside a user's home, so
  `fix.Action.NoFollow` refuses to read through a symlink — the account owns
  every component of that path while hostveil runs as root, and a preview
  renders whatever it read into a diff.

* **ci:** the measurement fixture builds a host on Fedora and Alpine, not only
  Ubuntu ([#698](https://github.com/seolcu/hostveil/issues/698)). Every
  published measurement was taken on Ubuntu, and not as a decision:
  `seed.sh` called `apt-get` and `systemctl` directly, so Ubuntu was the only
  host it could build. It goes through a distribution seam now, and the parts
  that genuinely differ are handled where they differ — `get.docker.com` does
  not support Alpine, `ufw` is Debian's where Fedora has firewalld, sshd's unit
  is `ssh` on one and `sshd` on the others, and an `sshd_config` that does not
  `Include` the drop-in directory gets the `Include` appended, because a
  drop-in nothing reads seeds nothing.

  What a distribution cannot express is recorded rather than skipped. Alpine
  ships no unattended-upgrade mechanism, so its updates axis reads better for a
  reason that has nothing to do with hostveil — and publishing that number
  without saying so is an absence read as an all-clear, which is the failure
  this whole tool is built against. The manifest travels into the measurement
  JSON, and a host seeded by an older copy reports it as *absent* rather than
  as an empty one.

  A published figure may also name the run it came off, so the page can carry
  several hosts side by side with each number still pinned to its own file.

### Bug Fixes

* **ui:** the published screenshot showed a severity scale hostveil had removed
  ([#697](https://github.com/seolcu/hostveil/issues/697)). `site/assets/tui.png`
  read `CRIT 8 · HIGH 16 · MED 22 · LOW 37` for two releases after the scale
  became three levels. Every other claim the site makes is held to the code by
  a test; the images were outside all of it.

  A PNG cannot be the pinned thing — it comes out of PIL and a font, neither
  pinned. What can be pinned is what the terminal drew, so the frame is
  committed as text and re-rendered on every test run. The dashboard cannot be
  re-rendered at all, so its *inputs* are hashed instead and the failure names
  which one moved.

  `scripts/ansi2png.py` could not have regenerated the asset in any case: it
  hardcoded Debian's font path, understood only truecolor — so a capture off a
  real host, which SSH degrades to xterm-256, came out monochrome — and drew on
  a `#090b12` ground that no theme in this project contains.

### Documentation

* the Go Report Card badge now reads "retired", so it is gone from both READMEs
  ([#695](https://github.com/seolcu/hostveil/issues/695)).

## [3.14.4](https://github.com/seolcu/hostveil/compare/v3.14.3...v3.14.4) (2026-08-12)

Two things 3.14.3 got wrong, found by looking at the parts of it nobody had
looked at yet: the dashboard, and the harness that audits hostveil from
outside.

### Bug Fixes

* **web:** the dashboard turned one panel header blue and left the other grey
  ([#691](https://github.com/seolcu/hostveil/issues/691)). 3.14.3 gave the
  design system a third thing colour is allowed to mean — structure — and
  spent it in the terminal on panel headers, the marker on the filtered
  domain, the detail headings and the footer's key letters. The dashboard was
  meant to take the same four and took three: the findings pane's title turned
  blue while the rail's header, two hundred pixels to its left, stayed the
  muted grey it had always been, and the rail's marker for the filtered domain
  kept a bone edge beside a filter chip that had already gone blue. Not a
  broken page — a page that looks deliberate and says something untrue about
  what its colours mean. Every structural rule is now listed in a test that
  requires the accent and forbids the heats.

* **ci:** a Lynis that never ran was recorded as a Lynis with nothing to say
  ([#693](https://github.com/seolcu/hostveil/issues/693)). The measurement
  harness exists so the numbers are somebody else's, and its Lynis instrument
  reported `hardening_index: null, warnings: 0, suggestions: 0` on a host
  where Lynis is not installed — which is the shape of a clean result. The
  missing binary was swallowed by `|| true` and the missing report by a bare
  `except FileNotFoundError`. That is the rule the scanner itself is built on,
  broken by the thing whose job is to audit the scanner. Both cases are
  explicit now, and the test runs the instruments in an environment without
  their tools rather than grepping them for the word "error".

  `DEVELOPMENT.md` also pointed at `/vagrant/scripts/measure/run.sh`, and the
  repository is mounted at `/hostveil` in that VM — three commands in the
  section whose whole purpose is letting somebody reproduce the published
  measurements, all of them "No such file or directory". A test reads the
  mount point out of the Vagrantfile and holds the docs to it.

## [3.14.3](https://github.com/seolcu/hostveil/compare/v3.14.2...v3.14.3) (2026-08-12)

The terminal UI, on the terminals it is actually used from. A screenshot of a
scan over SSH had 42 High findings on it and not one red pixel, and working
out why turned up three defects and one thing the palette had never been held
to.

### Bug Fixes

* **ui:** High severity was drawn in grey on every terminal that is not
  truecolor ([#687](https://github.com/seolcu/hostveil/issues/687)). SSH does
  not forward `COLORTERM`, so a remote session runs at 256 colors — which for
  a tool whose whole subject is remote servers is the normal case, not an edge
  one. The palette hexes are therefore inputs to a quantiser, and
  `ansi.Convert256` maps a colour into the 6×6×6 cube by truncating each
  channel and then takes the nearest *greyscale* entry instead where that is
  closer in HSLuv. One Dark's Crit sat on the wrong side of that line:
  `#e17079` came out as flat grey 246. The level that means "reachable now,
  from off-host, by someone holding nothing" was the only severity on the
  screen drawn without a colour. Crit moves twelve units with its hue
  untouched, and every theme is now held to what a 256-colour terminal
  actually renders — the heats must land on the cube and no two roles may
  collapse onto one index. That test found a second, unrelated collision:
  Nord's muted text and a Low finding were the same pixel value.

  Colour may now carry structure as well as risk and safety. Panel headers,
  the marker on the filtered domain, the detail pane's section headings and
  the key letters in the footer were all drawn in the same muted grey as the
  text they were meant to be distinguished from; they take a thirteenth
  palette role, each theme's own blue, which the dashboard reads through the
  same generated stylesheet. The heats keep their monopoly on risk.

* **tui:** the rail hid the domains worth looking at. Its meters fill by
  score, so a host with Container at 0, Dockerd at 10 and CVEs at 16 drew
  nothing at all for those while the two clean domains filled six cells of
  green — and an empty track is exactly how a *skipped* domain is drawn on
  purpose, so "nothing there" and "I could not look" arrived as the same row.
  A domain that ran now colours at least one cell and its score takes the
  band's colour, so a 0 reads red without the meter having to resolve it.
  Domains are separated by a blank line where the rows exist, since twelve of
  them packed into twenty-four with nothing between any two is what "hard to
  read" meant.

* **tui:** the rail's severity mix was cut through a count
  ([#688](https://github.com/seolcu/hostveil/issues/688)). `9 high · 16 med ·
  28 low` clipped to the column reported 28 findings of a severity it did not
  name and said nothing about the one it cut. The row is assembled a term at a
  time now and dropped between terms, never through one — the same call the
  chip bar already makes. The spelling is also chosen once for the whole rail
  rather than per domain, because the busiest domain has the widest counts, so
  deciding row by row abbreviated exactly the first row and left the eleven
  under it long.

* **tui:** the footer offered `press` and `any` as keys
  ([#689](https://github.com/seolcu/hostveil/issues/689)). Picking the key out
  of each hint took the first word of it, and two of the hints are sentences —
  including the confirmation for overwriting a file that rollback refused to
  touch. Only real bindings are picked out now.

## [3.14.2](https://github.com/seolcu/hostveil/compare/v3.14.1...v3.14.2) (2026-08-12)

Everything here came out of one session of actually running the demo instead
of testing it. The CVE domain had been trading coverage for speed on every
scan since it was parallelised, and the demo VM could not be started at all on
a stock Fedora workstation.

### Bug Fixes

* **cve:** four Trivy processes cannot share one cache
  ([#684](https://github.com/seolcu/hostveil/issues/684)). Image scans run
  four at a time, and Trivy's filesystem cache is a single-writer BoltDB — the
  process that loses the lock does not slow down, it exits. The same host
  scanned twice gave different answers: 1 of 7 images and a vulnerability axis
  of 44/100, then 3 of 7 and 25/100, against a true 16/100. The direction is
  the problem. An image that fails to scan contributes no vulnerabilities, so
  **the score improved the less of the host it saw** — and the worst case is
  the first scan on a fresh machine, which is the one people form an opinion
  from. The coverage machinery was not silent about it: every run carried
  `~ cve partial` and the axis was flagged Degraded. But a Degraded axis is
  still scored, deliberately, so the honest flag sat beside a number wrong by
  28 points. Fixed in two halves, neither of which works alone: the
  vulnerability DB is downloaded once before the fan-out (without it, all four
  scans race to fetch it and all four die), and each scan keeps its analysis
  cache to itself. The warm-up carries the flag it is testing and doubles as
  the capability probe, so a Trivy that rejects `--cache-backend memory` — it
  is experimental, and the value is newer than the flag — falls back to
  scanning one image at a time rather than failing every image.

* **demo:** the demo VM could not start on a stock Linux workstation
  ([#683](https://github.com/seolcu/hostveil/issues/683)). An unprivileged
  libvirt client resolves to `qemu:///session`, which has no management
  network, so the VM booted, never got an address, and Vagrant gave up minutes
  later with *"not yet ready for SSH"* — then left a domain behind that made
  the next attempt fail with *"Name demo_default is already taken"*, which
  reads as a name collision and leads nowhere. `run.sh` now pins the system
  URI, checks that libvirt is reachable before starting anything, and reports
  a leftover domain with the commands that clear it. The troubleshooting entry
  for a VM with no internet was pointing at `virbr0`, which this demo does not
  use, so following it changed nothing; it now reads the right bridge out of
  the network, keeps the rules across reboots, and accepts replies rather than
  new inbound connections — this VM publishes an unauthenticated Docker API on
  purpose. And a build that cannot find its Go toolchain now says the machine
  is half-provisioned instead of reporting it as a build failure.

* **demo:** the demo did not fit on the disk it asked for
  ([#685](https://github.com/seolcu/hostveil/issues/685)). The box ships
  8.7GB; a provisioned VM sat at 95% full with 492MB free, because the seven
  outdated images are 3.8GB and Trivy's DB is another 1.2GB. Trivy unpacks an
  image before scanning it, so the two 1.32GB images could not be scanned at
  all, at any level of concurrency — and a vulnerability score that skipped
  the heaviest images was better than the truth, on the machine whose whole
  job is to demonstrate finding problems. Now 24GB, which is sparse and costs
  what it uses. A first scan on a freshly created VM went from 4 of 7 images
  and 25/100 to 7 of 7 and 16/100 — the same answer every later scan already
  gave.

## [3.14.1](https://github.com/seolcu/hostveil/compare/v3.14.0...v3.14.1) (2026-08-11)

One fix, and two claims that had quietly stopped being checked. The fix is a
guard nothing could reach; the checks are the reason to care, because a guard
nothing walks past is exactly what a stale test looks like from the outside.

### Bug Fixes

* **web:** judge the whole authority in the dashboard's Host allowlist
  ([#680](https://github.com/seolcu/hostveil/issues/680)). The dashboard binds
  to loopback and then refuses any request whose `Host` is not one, because
  loopback binding stops the network but not DNS rebinding — a page on the open
  internet can resolve its own name to `127.0.0.1` and have the operator's
  browser deliver a request to a dashboard that applies fixes as root. The
  check split the authority with `net.SplitHostPort` and discarded the port.
  That function splits at the *last* colon and never asks whether what follows
  is a number, so `127.0.0.1:8787.evil.example.com` parsed as the host
  `127.0.0.1` — and the allowlist looked at the host, found loopback, and said
  yes to an authority naming somebody else's domain. Nothing was reachable
  through it, and the honest reason is the browser rather than anything here: a
  non-numeric port makes the URL unparseable, so the rebinding attack this list
  defends against cannot produce one. It is fixed anyway, because a host check
  that credits the wrong host is one refactor away from being load-bearing.
  Fixing it surfaced the opposite failure, which *is* reachable:
  `SplitHostPort` strips the brackets from an IPv6 literal only when it
  succeeds, so `http://[::1]/` — no port at all, exactly what a browser sends —
  arrived as the string `[::1]` and was refused by the very list that names
  `::1`. Both halves are now pinned by a table test, and one more through the
  middleware, because a guard that is correct but unwired protects nothing.

* **cmd:** `--addr` in `hostveil --help` took an argument it does not take. It
  is `host:port` and the port is not optional — `--addr 127.0.0.1` fails to
  listen at all. The CLI and interfaces pages, meanwhile, said a non-loopback
  `--addr` "answers nothing" and "refuses every request". It refuses everything
  that reaches the machine by IP or hostname, which is the claim that matters,
  but a forwarded port keeps working — the browser says localhost either way.
  Written the loose way, the reader who follows the `ssh -L` advice on the same
  line is told it cannot work.

* **ci:** the E2E step that proves a skipped domain is never scored 100
  selected domains on `.state == 3`, and
  [#656](https://github.com/seolcu/hostveil/issues/656) changed every enum to
  marshal as its name. From that commit on the selection matched no domain, so
  the step passed on every pull request without once looking at one — a vacuous
  jq selection is indistinguishable from a clean result. It selects by name
  now, and asserts that it matched something before asserting anything about
  it. Two lists with the same shape are pinned by tests in `internal/docs`
  rather than by memory: the nightly fuzz matrix against every `Fuzz*` target
  that exists, and CI's cross-compile loop against the targets
  `.goreleaser.yaml` actually ships. `.goreleaser.yaml` is itself validated in
  CI now — nothing read it until a tag existed, by which time the release was
  already public — and the shellcheck step finds all thirteen scripts in the
  repository instead of naming two of them.

## [3.14.0](https://github.com/seolcu/hostveil/compare/v3.13.0...v3.14.0) (2026-08-07)

The published measurement rested on a script nobody could see. Committing it
found two bugs in the fixture within an hour, and the run it produces now
covers **twelve domains instead of eleven** — so the headline score is *lower*
than 3.13.0's and the measurement is better.

### Features

* **cmd:** `scripts/measure/seed.sh` puts a throwaway host into the profile the
  published figures were taken on. It was the missing half of "reproduce it":
  the harness measures whatever host it is pointed at, and how to get that host
  lived outside the repository. Shellchecked in CI, sharing `demo/seed` and
  `demo/stacks` with the Vagrant demo so there is one description of this host,
  and it refuses to run anywhere that does not look like a container or a VM.

* **cmd:** `HOSTVEIL_LAYOUT`, and `--layout` on `serve`. The arrangement was the
  odd one out: `--theme` and `--glyphs` each resolve flag > environment >
  remembered > default through a tested function, and the arrangement had a
  flag, a picker and a file read by hand with no environment layer at all — so
  the one way to set something for a systemd unit or a shell profile did not
  exist for it. The dashboard, meanwhile, had no route to an arrangement except
  clicking the picker.

### Bug Fixes

* **check:** the measurement seeding wrote OpenClaw's config to
  `~/.config/openclaw/`, which the agent checker does not scan. The domain
  reported "no agent runtime found" on a host seeded to run two, and an
  excluded axis leaves the denominator rather than scoring zero, so the missing
  domain was worth points. Both seeders' paths are now held against the
  checker's own table by a test.

* **ai:** a trailing slash on `HOSTVEIL_OLLAMA_HOST` reached the request path,
  so `http://x:11434/` asked for `//api/version`. Ollama tolerates it, which is
  what let it survive — the symptom is the AI saying nothing, which is also
  what success looks like when no server is running. Trimmed at construction;
  the environment reference used to document the double slash rather than fix
  it.

* **cmd:** both environment-variable harvests were blind to a qualified
  constant, so `os.Getenv(pkg.Const)` fell out of the switch — a new variable
  would be undocumented *and* dropped by sudo's `env_reset` with every test
  green. That is the failure `carriedThroughSudo` exists to prevent, arriving
  through the test rather than the code.

* **ci:** the seed wrote an apt config for a package it never installed, which
  no distribution ships. Whether the package is present decides which
  remediation hostveil offers, so that host measured the wrong path: it got the
  apt install, the postinst left the existing `"0"` alone, and the fix
  completed with the finding still standing.

### Tests

* **ai** 29.8% → 91.5%, **history** 66.0% → 75.2%, **compose** 72.8% → 78.1%.
  Every function that talks to Ollama was untested; so were the two undo shapes
  that are not "write these bytes back", including the only code path whose
  undo is a *delete*; so was the list form of `environment`, which is half of
  what compose files in the wild use and whose failure mode is a file full of
  hardcoded passwords auditing clean.


## [3.13.0](https://github.com/seolcu/hostveil/compare/v3.12.0...v3.13.0) (2026-08-07)

hostveil can turn a firewall on now. On the measured host that is worth more
than every Compose edit put together: the port it closed belongs to a Redis
hostveil reports and *declines* to fix, and it stopped answering anyway. Ports
answering from off the host go **7 → 1** on the seeded server, and the score
**43 → 66**.

### Features

* **fix:** `firewall.inactive` — a High finding on every host without a
  firewall — is fixable. What was missing was never the commands; it was that
  the checker recorded no SSH port, so hostveil could not know what to keep
  open. It reads one from the kernel's socket table now, the port sshd is
  *actually* serving on rather than the one its config claims, and allows that
  port before enabling the policy. **No port, no fix**: a host on 2222 whose
  port could not be read gets nothing rather than a lockout that looks like
  knowledge. ufw only, because the other front-ends take rules different enough
  that a guessed one is a lockout by another route.

* **model:** the same mistake made four times is not four mistakes. A compose
  file where four services all lack `user:` is one line missing, written four
  times, and the score charged it as four independent risks — so an axis was
  buried for running more services rather than worse ones. Repeats of one
  finding ID on one axis are damped harmonically now: the second costs half its
  weight, the third a third, never zero, because at ten the mistake is
  systematic. Within an ID the heaviest instance is sorted first and pays full
  price, which is what keeps the score independent of the order findings
  arrive in.

* **site:** a Korean-speaking reader lands on the Korean page. Once, guarded by
  the choice they made last time, because a redirect that overrides an explicit
  language switch is worse than no redirect.

### Documentation

* **docs:** the scoring model is in the README, in both languages. The file
  most people read asked them to trust a 0–100 number through eight sections
  and never said how it was computed.

* **docs:** both READMEs are rewritten. One habit was everywhere — a sentence,
  an em-dash, then the sentence explaining itself — forty-two of them in
  English and forty-three in Korean, and a reader learns to skip the half after
  the dash, which is where the facts were. The Korean was English clause
  structure carried over word by word and is now written as Korean.

* **site:** the marketing page carries a measured result. It had none, which is
  the one place a reader decides whether to trust any of it.

### Bug Fixes

* **docs:** the measurements page picked its run by filename, so a second run
  on one day sorted *before* the first and the page would have been checked
  against the older one while every number came from the newer. It reads
  `measured_at` now. Its narrative is pinned too — the port lists, the cleared
  CIS check IDs, and the SSH and container axes — after the prose went stale
  claiming the containers were stubs that blinded the external scan while the
  scan was reporting seven ports.

## [3.12.0](https://github.com/seolcu/hostveil/compare/v3.11.0...v3.12.0) (2026-08-07)

The six arrangements shipped behind a picker in 3.11.0 are settled: **C ·
Console is the default in both interfaces**, and the other five stay. The rest
of this release is what deciding that made visible — the bands that drew
nothing, the lines that did not meet, and the margins that did not hold — plus
a Korean README and a measurement harness that now measures the path an
operator actually takes.

### Features

* **ui:** the six arrangements are settled. **C · Console — the domain rail
  down the left — is the default in both the terminal and the browser**, and
  the other five stay in the picker rather than being deleted. The comparison
  settled a different question than it asked: there is no arrangement that is
  right at 1440px and at 80 columns and on a host with four findings and on
  one with forty, so one of them answers the common case and the picker
  answers the rest. C leads because the rail is the only place a domain nobody
  could scan is both visible and explained; every other arrangement leaves
  that to a banner. Both registries now lead with it, and neither describes
  itself as temporary any more.

* **docs:** the measured-results page and both READMEs carry a run against a
  real ARM64 server with the services actually running, and the numbers now
  cover the reviewed path: ports answering from off the host **7 → 2**, CIS
  Docker Benchmark **16 → 20 pass**, Lynis's hardening index **56 → 60**, the
  SSH domain **18 → 100**. What did not move is on the page in the same
  detail — the container domain never leaves 0/100, six image updates left the
  CVE axis where it was, and two of Lynis's three warnings are an account
  hostveil finds and refuses to delete.

* **fix:** `fix --all --review` applies the Review fixes too, each through its
  first alternative. "Fix everything that needs no human" and "fix everything
  hostveil can" are different requests and only the first had a command, so
  every SSH hardening option, every kernel parameter and every image update
  needed one invocation apiece. The classification does not move — a Review fix
  is still one that can cut off access to this host or has more than one
  defensible answer — and the two lists are printed and counted separately, so
  saying yes to them is still saying yes to them. On a seeded host it is the
  difference between the SSH domain reaching 44 and reaching 100.

* **updates:** enabling automatic security updates is an Auto fix on a host
  where the mechanism is already installed, which on Debian and Ubuntu is the
  usual state. The remediation there is two keys in
  `/etc/apt/apt.conf.d/20auto-upgrades` — a file edit, reversible from a
  checkpoint — and it was being served by the same `apt-get install` a host
  without the package needs, which made an exec action out of a two-line edit
  and put the most ordinary hardening step there is behind a human.

* **ci:** the measurement harness measures the *reviewed* path too. It ran
  `fix --all`, which applies Auto fixes only — the unattended path, and
  deliberately the most conservative thing hostveil does. It is not the path
  an operator takes: they read a Review fix, decide, and accept it, and the
  fixes that need that decision are the ones that change the most, because
  every SSH hardening option is Review. A fifth phase now accepts every Review
  fix and counts how many left a checkpoint, since an exec fix leaves none and
  the rollback phase cannot put it back. On a seeded ARM64 host the difference
  is the whole argument: Lynis's hardening index moved 56 → 57 for the
  unattended path and 56 → 60 once the reviewed fixes were accepted.

### Bug Fixes

* **ci:** the measurement harness could not start on a host that had never
  applied a fix — which is every host its own documentation points at. `grep`
  matched nothing, exited 1, and `set -euo pipefail` ended the run two lines
  in. Invisible on every host it had been run on before, because they all had
  checkpoints.

* **web:** three bands of empty padding under the axes strip, on every scan
  with nothing to put in them. `.delta`, `.domains` and `.status` each set
  `display` in the stylesheet, which beats the `hidden` attribute at equal
  specificity, so hiding them in JavaScript did nothing to their layout — a
  first scan (no previous scan, no trend, no status flash) drew three rules of
  nothing, in every arrangement. Each now has its own `[hidden]` rule, and a
  test walks the markup for elements that start hidden so the next band is
  covered before it ships. Deliberately not a blanket
  `[hidden] { display: none !important }`: the verdict band and the rail stay
  hidden in the DOM and are un-hidden per arrangement, and that would have
  deleted the rail from the two layouts built around it.

* **tui:** the grid meets itself. Horizontal rules now carry `┬` where the
  body's columns begin, `┴` where they end, and `├` where a column's own
  divider — the detail pane's, the verdict band's — arrives at the separator
  beside it. Previously a rule ran straight through a vertical line and the
  vertical line stopped dead at a rule: the same defect from two sides.

* **tui:** the findings list lines up. The severity label was padded in the
  arithmetic that laid a row out and not in the render, so every `MED` and
  `LOW` row was drawn a column narrower than its budget — the id column
  stepped left on those rows and the right-aligned service stopped short of
  the pane separator. The id field was also a fixed 13 columns, which several
  real ids overrun (`cve.outdated-image` is 18), pushing their titles right of
  every other title on the screen; it is now measured from the ids actually on
  screen and bounded. The history screen had the same fault and the same fix.

* **web:** the inline arrangement broke on the second thing you did. It parks
  the one detail node inside the findings list, under the row that opened it,
  and the next list rebuild — a filter, a fix, a rescan — deleted it. Every
  lookup after that returned null, so opening a finding, previewing a fix and
  pressing History all threw until the page was reloaded. The renderer now
  moves the node back out before it rebuilds, and a test pins that it happens
  in that order.

* **web:** the axes strip no longer overflows its own grid cell — its three
  parts added up to four pixels more than the track they were laid into, which
  at two columns overflowed the window — and at a phone width the spark strip
  (triage, inline) scrolls instead of dividing 480 pixels between twelve
  domains, which had left twelve one-letter labels: the score survived and
  what it was a score *of* did not.

* **tui:** one margin per screen, and wrapped text keeps it. The applied-fix
  message indented its first line two columns and continued at zero; the
  preview's alternatives sat at two under a label at zero, its commands at two
  under a label at zero, and its warning at zero; the rollback screen mixed
  all three; the detail screen had no margin at all while the pane beside the
  list had one. There is now one vocabulary — a body margin, a step for nested
  lists, a narrower one inside a column — and the wrap applies it to every
  line rather than to the first, which is what the dashboard gets for free by
  padding the box instead of the text.

* **tui:** the grid also holds where a terminal draws East Asian Ambiguous
  characters wide. Every glyph the frame is built from — `─ │ ┬ ▌ ░ █ · ✓` —
  is in that class, and an operator whose terminal renders it double-width
  says so with `RUNEWIDTH_EASTASIAN=1`, which hostveil honours. Four places
  counted runes where they should have counted columns: the rule was built as
  `width` dashes and came out twice the terminal, so it was cut back and every
  junction past halfway went with it; the column arithmetic charged one column
  for a two-column separator; and the pick marker was two columns for an
  unmarked row and three for a marked one, which stepped the whole list in and
  out down its left edge. All four are measured now, and the grid tests run in
  both modes.

* **tui:** the rail says what the dashboard's says — `3 high · 1 med · 2 low`
  rather than `3H·1M·2L`, falling back to the compact form only where the
  column cannot hold the words — and its head counts findings the way the
  browser's does. The verdict band's note is dropped whole when it does not
  fit rather than being cut mid-word, which had been ending a sentence about
  backups at "reversible from histo".

## [3.11.0](https://github.com/seolcu/hostveil/compare/v3.10.0...v3.11.0) (2026-08-06)

The severity scale is three levels instead of four, and hostveil now shows
its work: why a finding has no fix button, how the 0–100 score is computed and
why that arithmetic, where the tool actually runs, and what independent
auditors say about a host it has fixed. Three checkers stopped answering
questions about hosts they had never examined.

**If you read `scan --json` or a scan snapshot, read the first two entries.**
Severity is `high` / `medium` / `low` rather than four Trivy levels, and every
enum goes out as a name rather than an integer. `scan`'s exit code and the
SARIF export mean exactly what they always did, and snapshots written by any
older version still read.

hostveil also looks different: one brand mark instead of four, One Dark as the
default theme, a terminal list that finally says what shape a scan is, and
optional Nerd Font symbols. Six candidate arrangements of the same screen ship
in both the terminal and the browser behind a picker; **they are temporary and
will be gone once one of them is chosen.**

### Features

* **model:** severity is three urgency levels, not four Trivy ones. A finding
  is now **`high`** (reachable or usable right now, from off the host, by
  someone holding nothing), **`medium`** (a boundary that gives way to a
  foothold, a guessed credential, or a local account) or **`low`** (no known
  path today; it narrows what a future compromise reaches). Critical / High /
  Medium / Low came from Trivy so a CVE's published rating could pass straight
  through — but vulnerabilities are rolled up per image now, so what reaches a
  finding is one level for the whole image rather than a rating per CVE, and
  outside that domain the fourth level was asking a question a config file
  cannot answer. "How bad is a container running as root" depends entirely on
  what the container does; how much stands between an attacker and it does
  not.

  The definitions above are the taxonomy and the names only carry the order —
  which is the one job a name has on a filter chip, in a SARIF level, or in a
  line of `--json`, and it is why they are the ordinary three rather than
  something more descriptive.

  **`high` is exactly what Critical and High were together**, so nothing a
  pipeline reads has moved: `scan` still exits 1 on the same set of findings,
  and the SARIF export still maps them to the same three levels (Critical and
  High were both `error` already). Both are pinned against the *old ordinals*,
  read back through the legacy unmarshal, because the old constants no longer
  exist to name. If you also run Trivy directly, note that a vulnerability it
  calls CRITICAL arrives here as `high`: three levels and four do not line up
  by name.

  Scores do move. A finding that was High now costs half of an axis's
  remaining credit rather than a third, which is the point of the merge — if
  it is reachable now it is the top level, and the top level costs half. The
  seeded demo host goes from **38 to 32**, with SSH hardening moving 26 → 19
  as `ssh.rootlogin` joins the top level.

  Two conditional escalations collapsed, and that is the taxonomy working
  rather than information being lost. `dockerd.api-unauthenticated` no longer
  drops a level when the daemon is rootless, and `agent.gateway-exposed` no
  longer rises one when a listener is confirmed with no firewall: blast radius
  and confidence are not urgency. Both differences are still reported, in the
  description and the evidence, where a reader can weigh them.

  `ScoreAxis`'s four hardcoded count fields became `counts`, a list projected
  from the severity table — the last structural four in the model, and the
  reason a change of scale used to touch the score struct, its JSON, three
  renderers and their tests.

* **model:** `scan --json` names its enums instead of numbering them. `severity`,
  `source`, `remediation` and a domain's `state` go out as lowercase words
  (`"high"`, `"ssh"`, `"review"`, `"degraded"`) rather than as the bare integers
  every consumer had to keep its own ordering table for — including hostveil's
  own dashboard, which was handed a generated lookup table so it could read its
  own API. Snapshots written by an older version still read: unmarshalling
  accepts a name *or* an integer, for one release, so a host's previous scan is
  not lost and its next scan converts it. Nothing writes integers any more.

* **site:** where hostveil runs, how it is extended, and every environment
  variable it reads — three things the docs either got wrong or never said.

  The platform claim led with "Linux and macOS" on two pages and buried the
  honest sentence dozens of lines down, where it said macOS "has nothing to
  look at". Neither half was true. There is now a *Running it on macOS*
  section: ten of the twelve domains report N/A — seven find nothing on their
  own, three are excluded deliberately because they would otherwise answer a
  question they had not asked — two run, and the score is a real number
  averaged over a fifth of the weight. Including the part worth knowing before
  you try it on a laptop: an SSH fix on a Mac rewrites a real
  `/etc/ssh/sshd_config`.

  Extensibility was one sentence — "write one package and register it" — for
  something that touches a domain table, a weight rebalance that has to keep
  the total at 100, a registration, rows in two languages of two different
  tables, a decline reason per unfixed finding, and about eleven failing tests
  until each is done. The contributing page now says so, and separates it from
  the two things that genuinely are small: a rule, and a fix.

  And there is an environment-variable reference. Around thirty variables were
  scattered across five pages or documented nowhere at all — including the two
  that decide whether hostveil re-executes itself as root, which a test
  asserted were "documented" while nothing a user could read mentioned them.
  A sweep over the source keeps the page honest in both directions.

* **site:** the scoring model is published, on a page of its own. It was
  restated in fragments across `checks.html` and the FAQ — a severity-share
  table, a weight table, and a paragraph — while the argument behind it lived
  in a Go doc comment. `docs/scoring` now carries the whole thing: the
  per-axis multiplicative formula, why it is multiplicative (the additive
  model it replaced clamped an axis after two findings and made every
  finding after that free, so a host with 27 container findings scored the
  same as one with 3), a worked example from a real 83-finding scan with the
  arithmetic shown line by line, all twelve axis weights with the argument
  for each, renormalization and what a skipped domain does, why an unfixable
  finding weighs a quarter, and a section on what the number cannot tell you.

  A cap is a weight, never a threshold, and the page says so before it shows
  the table. It also says which weights have no positive argument for their
  exact number — most of them — and what they have instead, which is a
  defended position relative to their neighbours.

  The twelve weights are now pinned on that page too. The existing guard
  reads the checks table and cannot see these rows (it requires a two-cell
  row and these carry an argument column), so they could have drifted from
  the code with a green build, on the page that presents itself as the whole
  model.

* **fix:** a finding with no fix button now says why. hostveil has always had
  the reasons — the doc comment on `fix.Default()` is pages of them, argued
  finding by finding — in a place no user will ever read. Each is now one
  sentence attached to the finding it is about, shown in `hostveil explain`,
  the terminal's detail pane and the dashboard. "Manual" is a decision
  somebody made about a specific remediation, and in an interface it was
  indistinguishable from a finding nobody had looked at.

  Forty-two findings carry one. They say what *stops* the automation, never
  what the finding is: `accounts.uid0` reads "userdel orphans every file the
  account owns with no checkpoint to undo it, and hostveil cannot tell a
  backdoor from a deliberate second root", not a restatement of the title.
  Two tests hold the register and the sentences together — a declined finding
  with nothing to say fails, and a sentence for a finding that has a fix
  fails too.

* **site:** the fixing page now publishes the standard instead of the labels.
  It had a four-row table saying what Auto-fix, Review, Manual and Unavailable
  *are* and nothing about how a finding lands in one. It now carries the three
  criteria an Auto-fix has to meet — reversible, recoverable in practice,
  unambiguous — each with a worked example from the tool, the reason a failing
  criterion sometimes means Manual rather than Review (Review needs two
  independent alternatives; one option and no way to make it safe is Manual),
  and the two-source resolution rule with a finding you can watch it happen
  on. In both languages, pinned against each other by a new test.

* **ui:** one brand mark, One Dark by default, six arrangements, and Nerd Font
  glyphs ([#649](https://github.com/seolcu/hostveil/issues/649)). hostveil had
  *four* brand marks — the dashboard's favicon and status-bar mark were two
  colourings of one figure, and the marketing site had two more that shared
  nothing with them. They are now one drawing, a chip, byte-identical across all
  four surfaces and held there by a test, with both lockups optically aligned.
  The Instrument palette is gone and One Dark is the default; four of its twelve
  roles are moved — three lifted in HSL lightness by the smallest step that
  clears the contrast floors every theme here is held to, and the foreground
  lifted as a judgement rather than a floor, because an editor sets a few
  hundred glyphs on screen and this sets thousands. The terminal list gains
  what the dashboard has always had above the fold: a count per severity, how
  many findings hostveil can offer a fix for at all — Auto *and* Review, which
  is what the dashboard's chip has always counted — and, for each domain that
  did not fully run, the reason the checker gave, instead of an unexplained
  `N/A`. `scan` no longer double-spaces its findings, which halves the
  scrollback on an ordinary host. And `--glyphs nerd` draws the status markers from a patched Nerd Font: opt-in,
  because a terminal cannot be asked what font it is using and a missing glyph
  is drawn in the same single cell a present one would be. Any Nerd Font build
  works, Mono or not — verified by reading the tables of eighteen font files.

* **ui:** six arrangements of the same screen, in both interfaces, behind a
  picker ([#649](https://github.com/seolcu/hostveil/issues/649)). `l` in the
  TUI, a dropdown in the dashboard, `--layout` on the command line. This is
  scaffolding for a decision rather than a setting to keep: an arrangement that
  reads well in a 1440-column browser and badly in an 80-column terminal is not
  one hostveil can adopt, and the only way to find that out is to drive both
  against a real host. The default is unchanged, so an operator who never opens
  the picker sees no experiment. **When one is chosen the other five go, and
  `--layout` and `l` go with them.**

### Bug Fixes

* **cve:** the vulnerability rollup counted its most severe findings twice.
  `summary()` and `evidence()` each walked a severity list written out in
  `cve.go` rather than asking the model, and that list was the four-level
  scale — so when Critical and High merged into one constant, both rows
  stayed and the same constant was read twice. An image whose worst
  vulnerabilities were all top-severity described itself as "2 high, 2 high,
  1 medium". No count was wrong; each was right and said twice.

* **web:** the dashboard's verdict headline had been dead since the severity
  levels were renamed. It counted findings whose severity was the string
  `"critical"`, a name the model stopped using, so the count was always zero
  and the headline it gates never appeared again — the panel silently fell
  through to the band verdict on every host. It now asks the model for its
  top level instead of spelling one.

* **web, site:** severity colours are pinned to the model. The dashboard
  builds every severity class name at runtime (`.finding.<name>`,
  `.chip.c-<abbr>`) while the stylesheets have them typed in, so renaming a
  level silently unstyles the findings list, the filter chips and the
  landing page's example findings — which reads as a low-contrast theme
  rather than as a broken stylesheet, and had already shipped that way on
  the landing page. Tests now walk `model.AllSeverities()` against both
  stylesheets, in both directions.

* **check:** hostveil reported a firewall finding on every Mac, for a firewall
  it had never looked for. The firewall checker probes ufw, firewall-cmd, nft
  and iptables; on a host with none of them installed nothing fails, and the
  absence of a failure was read as the absence of a firewall — a top-severity
  `firewall.inactive` on a machine whose packet filter is pf and whose
  application firewall is socketfilterfw, neither of which appears anywhere in
  the codebase. Two more domains did the same thing more quietly: `accounts`
  read the stub `/etc/passwd` macOS ships and then advised re-running with
  sudo for an `/etc/shadow` that does not exist, and `agent` enumerated homes
  out of that file keeping uid 0 and 1000–65533, found only `/var/root`
  because macOS accounts start at 501, and reported "no agent runtime" about a
  host whose `/Users` it never opened.

  The result was not the N/A score the docs implied: the firewall and file-
  permission checkers are unconditionally available, so a Mac produced a
  plausible-looking number resting on a false finding. All three now skip with
  a reason, through one gate — `platform.AuditableOS` — because "what host is
  this" belongs with the rest of the host questions rather than in three
  checkers deciding it three ways. Nothing changes on Linux.

* **tui:** setting `RUNEWIDTH_EASTASIAN` made the terminal UI measure itself
  two ways at once. It is what an operator sets when their terminal draws East
  Asian Ambiguous characters wide, and it is common in CJK setups. lipgloss
  honours it, in a package init that mutates state hostveil cannot reach;
  hostveil's own measurement ignored it. So the ellipsis `truncate` appends and
  the arrows and bullets in the status lines were one column to one half of
  the UI and two to the other — `truncate` cutting to one budget while
  `padRight` padded to another, which is the exact failure `internal/textwidth`
  exists to prevent, arriving through the door it left open. Measured on
  `"→ … ●"`: 5 columns against 8. It is honoured now, with the same parse rule,
  and a re-exec test pins the agreement on the side of the variable that used
  to break it.

* **cmd:** `HOSTVEIL_DEBUG=1 hostveil scan` did nothing on the path most
  people take. Auto-elevation re-execs through sudo, whose `env_reset` keeps
  only what `env_keep` names and never an application's own variable — a fact
  the elevation code states in a comment, having drawn the conclusion for
  exactly one variable while it applied to every one a user sets. So the line
  printed in `hostveil help`, in the README and on both troubleshooting pages
  as the thing to attach to a bug report produced no trace at all, with no
  error and nothing to suggest the variable had been dropped. `HOSTVEIL_THEME`
  and `HOSTVEIL_GLYPHS` were ignored the same way. They are now carried across
  the re-exec explicitly. CI never caught it because the end-to-end job runs as
  root with `HOSTVEIL_NO_SUDO=1` — both of the branches that skip the re-exec.

* **fix:** four claims in the register of deliberately-unfixed findings were
  wrong, found while turning it into user-facing text. `userdel` does not
  take the home directory unless it is given `-r`, which the finding's own
  how-to-fix does not recommend; `dockerd.api-tls-unverified`'s remediation
  is requiring client certificates, not removing the TCP endpoint;
  `dockerd.socket-world-writable`'s socket is recreated by systemd, not by
  dockerd, which the finding's own text already said; and five of the seven
  agent findings can only come from OpenClaw, so the register's Hermes
  argument does not apply to them.

* **core:** remediation is now settled the way every comment in the repo says it
  is. `classify`'s rule — whichever of the checker and the fix registry demands
  more human involvement wins — applied only when the checker's own answer was
  already fixable, so a checker declaring **Manual** or **Unavailable** was
  overruled by any fix builder matching the ID. The two packages that rely on
  the rule by name were saved instead by their builders erroring, which is
  correct by accident from the layer that was not making the claim. And
  `PreviewFix` ran only half the resolution, so an exec fix a finding correctly
  carried as *Review* previewed as *Auto-fix* — on exactly the fixes where "safe
  to apply unattended" is the claim being ruled out.

* **sitegen:** three docs guards were passing on things they did not check: the
  scoring tripwire never read the constant that decides whether one Critical
  costs half an axis, the checks table's Fix column was compared as a
  fixable/not-fixable bool so Auto and Review were the same answer, and the
  fixing page's classification table had four rows against a five-value enum
  with nothing saying which was missing.

* **tui:** a filter chip could be cut through the middle of its count
  ([#650](https://github.com/seolcu/hostveil/issues/650)). The chip row was
  clipped to whatever width it had, which is right for a title and wrong for a
  row that is nothing but numbers: in the arrangement with a rail on one side
  and a detail pane on the other, `FIXABLE 38` was drawn as `FIXABLE 3`. A
  clipped word is visibly clipped; a clipped count is a different number. The
  row now drops whole chips and says how many it dropped, and never drops one
  that is on — for the domain filter, that chip is the only place the domain is
  named.

* **tui:** the domain rail did not say why a domain had not run
  ([#650](https://github.com/seolcu/hostveil/issues/650)). It spent a second row
  per domain only when it had better than two rows each, and with twelve domains
  that needs more rows than a 30-line terminal has — so the reason, which is the
  difference between "nothing there" and "I could not look", was the first thing
  dropped on every real host. A domain that did not run now keeps its reason
  whatever the room; the severity mix gives way instead.

* **ui:** the two interfaces drew one arrangement two different ways
  ([#650](https://github.com/seolcu/hostveil/issues/650)). The dashboard's
  domain rail runs the full height of the window with the verdict beside it; the
  terminal put the verdict across the top and started the rail underneath. And
  the dashboard's per-severity button said "Fix the N safe" while only selecting
  them for the batch bar — which is what it should do, and what the terminal's
  `m` does, but not what it said. Both now match.

* **cmd:** `--glyphs nerd` drew one of three coverage markers from the wrong set
  ([#650](https://github.com/seolcu/hostveil/issues/650)). `scan` prints
  skipped, partial and errored domains as one block. Only the skipped line went
  through the chosen symbol set, so a patched glyph sat next to two ASCII ones,
  which reads as two kinds of remark rather than three degrees of one.

* **install:** needing root is not the same as needing sudo
  ([#647](https://github.com/seolcu/hostveil/issues/647)).

## [3.10.0](https://github.com/seolcu/hostveil/compare/v3.9.0...v3.10.0) (2026-07-30)

A new check for who owns your sensitive files, and two fixes for hostveil asking
the host a question in one language and reading the answer in another. If your
system is not in English and you run Debian or Ubuntu, **the pending
security-update count was wrong** — read the first fix below.

### Features

* **check:** check who owns a sensitive file, not just its mode
  ([#611](https://github.com/seolcu/hostveil/issues/611)). The file-permission
  rules asked how much access the permission bits grant and stopped there,
  which is half the question. Mode 0600 grants everything to the owner and
  nothing to anyone else — so an `/etc/shadow` at 0600 owned by an ordinary
  account hands that account every password hash on the host, and the old check
  called it clean, because 0600 is exactly what it wants to see. Ownership is
  now checked for every file in the table, independently of the mode, so a file
  with impeccable bits is still examined. One finding covers all of them, since
  the remedy is the same in every case and when this goes wrong it has usually
  gone wrong to several files at once — a restore run as the wrong user, an
  archive extracted with its own ownership. It is Manual on purpose: a restore
  point records a file's contents and its permissions and has nowhere to put
  its previous owner, so this would be the only change hostveil makes that it
  could not undo. Hosts with a wrongly-owned sensitive file will see their score
  drop, which is the point — they were being scored clean on a file the wrong
  account could read.

### Bug Fixes

* **platform:** ask the host in a language the parsers can read
  ([#644](https://github.com/seolcu/hostveil/issues/644)). hostveil ran the
  host's own tools and read their output, and it ran them in whatever language
  the operator's system is set to — `sudo` passes that setting through. But it
  looked for English. The one that mattered: apt marks an upgradable package
  with `[upgradable from: …]`, which is translated in twenty-one languages
  including German, French, Spanish, Japanese, Russian and Chinese. On such a
  host every line was skipped and the count of waiting security updates came
  out **zero, however many were actually waiting** — a clean report on a machine
  with unapplied security patches. Commands now run with the language pinned, so
  every one of these parsers reads what it was written for. The same change
  covers apt's and dnf's other messages and the firewall and port checks, which
  had the same exposure without having broken yet.

* **cmd:** the re-exec loop guard could not fire, because sudo strips it
  ([#645](https://github.com/seolcu/hostveil/issues/645)). When run without
  root, hostveil re-runs itself under `sudo`. It marked the second run so it
  would not try a third time, and `sudo` discarded that mark — it clears the
  environment by default and keeps only a short list of variables it knows
  about. So on a host configured to give `sudo` a target other than root,
  hostveil would have re-run itself without end, asking for a password each
  time. The guard now keys on a marker `sudo` sets itself, which is present even
  when the target is not root. If it ever reads that marker wrongly, hostveil
  simply scans without root and says which checks it had to skip, which is the
  safe direction to be wrong in.

## [3.9.0](https://github.com/seolcu/hostveil/compare/v3.8.6...v3.9.0) (2026-07-30)

A twelfth detection domain, and five fixes. Three of them are the same mistake:
hostveil working out for itself what another tool's layered configuration adds up
to, and reaching a different answer than the tool does. Two of those let a
Critical finding go unreported on an ordinary host. The other two fixes are a
warning about your restore points that was not true, and an access token that
outstayed its usefulness in the address bar.

### Features

* **check:** audit the sandboxing of the services you installed yourself
  ([#638](https://github.com/seolcu/hostveil/issues/638)). Roughly half of a
  self-hosted server is not in a container. The container audit reads what each
  service declares — privileged, running as root, no-new-privileges off — and a
  service started by a unit file has exactly the same decisions made about it:
  whether it can gain privileges through a setuid binary, whether it can write
  to `/usr` and `/etc`, whether it can read every user's home directory,
  whether it shares `/tmp` with the rest of the host. Nothing looked at any of
  it before. The new domain asks systemd for each unit's *effective*
  configuration, so what it reports is what the service will actually run with
  rather than what some file says, and it audits only the units you installed
  yourself — your distribution hardens its own on its own schedule, and
  reporting on those would bury your services under findings about software you
  did not choose. Severity follows the account: the privilege-escalation rule
  matters most on a service running as somebody other than root, and the two
  filesystem rules matter most exactly where it matters least. All four are
  Manual on purpose — the change is two lines, but a service that needs what
  one of these protections hides fails at its next restart, which on a
  self-hosted box is the next reboot. Adding the domain moved the score
  weights: six axes gave up one point each to fund it, so scores will shift
  slightly on hosts where those domains apply.

### Bug Fixes

* **compose:** audit the project docker composes, not its first file
  ([#641](https://github.com/seolcu/hostveil/issues/641)). `docker compose up`
  reads `docker-compose.override.yml` with no flag asked for, and `-f base.yml
  -f prod.yml` is the standard production pattern, so a project made of several
  files is the ordinary case. hostveil read the first one and audited that.
  That is not a partial view — it is a wrong one, and in the dangerous
  direction, because compose *adds* port mappings across files rather than
  replacing them. A base file binding a database to localhost plus an override
  publishing it is published on every interface; hostveil saw the localhost
  binding, found nothing, and passed the host. An exposed datastore is the
  worst finding the container domain has. It now asks docker for the merged
  configuration, which also resolves `${VARIABLES}` the way they will resolve
  at run time instead of reading them as literal text. Where docker cannot
  answer and the project has several files, the project is reported as ground
  the scan did not cover rather than guessed at from one of them.

* **check:** a docker.service systemd never loaded is not a unit with no flags
  ([#642](https://github.com/seolcu/hostveil/issues/642)). Every mainstream
  package puts the Docker daemon's listening socket on its service unit, which
  is why hostveil reads the unit as well as `daemon.json`. Two things stopped
  it. Asking systemd about a unit it does not have succeeds and prints nothing,
  so "the unit was never read" was indistinguishable from "the unit carries no
  flags" — which is the state of every host whose daemon runs under a
  differently-named unit, including snap installs and rootless daemons. And the
  two sources were treated as covering for each other in both directions when
  only one direction holds: having read the unit does make up for an unreadable
  `daemon.json`, but the reverse is not true, and most hosts have no
  `daemon.json` at all. So the ordinary failure — no `daemon.json`, unit not
  read — reported "audited, no sockets configured". An API served over TCP
  without TLS client verification is unauthenticated root for anyone who can
  reach the port, and it could go unreported while the score said the daemon
  had been checked. A host that does not run systemd now reports these rules as
  not audited rather than clean: the flags live somewhere hostveil cannot read,
  and saying so is the honest answer.

* **check:** name the file that decides a kernel parameter, and fix that one
  ([#635](https://github.com/seolcu/hostveil/issues/635)). The kernel-hardening
  fix wrote a new file under `/etc/sysctl.d`, reported success, and recorded a
  restore point. On Ubuntu that file loses. `/etc/sysctl.conf` — where
  operators have been told to put kernel settings for thirty years — is read
  after everything in `/etc/sysctl.d`, so a value set there came back at the
  next boot with nothing to explain why. The scan now works out which file
  actually decides each parameter and says so, and the fix corrects that file
  instead of writing one that cannot take effect. Where the deciding file
  belongs to a package rather than to you, hostveil declines to edit it and
  says the drop-in will not work, rather than reporting a success the next boot
  contradicts.

* **history:** a Save that never finished is not damaged recovery history
  ([#640](https://github.com/seolcu/hostveil/issues/640)). `hostveil history`
  could report that some of your restore points were unreadable and could not
  be rolled back, when nothing had been lost. A restore point is written
  backup-first and only becomes real when its metadata lands, precisely so that
  an interrupted one is something nothing will try to restore from — and since
  the backup is taken before the file is changed, one that did not finish means
  the file was never touched. Listing tried to read them anyway and reported
  the leftovers as damage. It did not take a crash: a full disk was enough to
  leave one behind permanently, so the warning repeated on every later run.
  Metadata that exists and cannot be read is still reported, because that is a
  fix which was applied and can no longer be undone.

* **web:** drop the dashboard access token out of the address bar
  ([#636](https://github.com/seolcu/hostveil/issues/636)). `hostveil serve`
  prints a URL carrying an access token, because a terminal has no other way to
  hand a credential to a browser. The dashboard converts it to a session cookie
  on the first request and never needs it again — but the copy in the address
  bar stayed, in the history entry, in a bookmark made without thinking, and in
  every screenshot pasted into an issue. The page now removes it as soon as it
  loads. Reloading works for as long as the session lasts; past that the
  dashboard asks you to reopen the URL it printed, which the running `serve`
  command is still showing.

## [3.8.6](https://github.com/seolcu/hostveil/compare/v3.8.5...v3.8.6) (2026-07-29)

One fix, for an SSH remediation that reported success and left the setting it
named exactly as it found it.

### Bug Fixes

* **fix:** keep sshd_config edits out of Match blocks
  ([#633](https://github.com/seolcu/hostveil/issues/633)). A `Match` block in
  sshd_config applies only to the sessions it selects, so hostveil's SSH
  detection deliberately stops reading at the first one — every SSH finding is
  a statement about the global settings above it. The part that *edits* the
  file was meant to work the same way and did not: its guard against touching
  Match blocks could never run, because the test above it had already narrowed
  the line to the directive being changed. Two things followed. A setting
  written inside a Match block was rewritten as though it were the global
  default, changing SSH's behaviour for the users that block selects — chosen
  deliberately by the operator, and never what the finding was about. And when
  the setting was absent, it was added at the end of the file, which on a
  config ending in a Match block put it inside that block. The second case is
  the one an ordinary host hits: password authentication is reported whenever
  no global value is set, since SSH defaults it to on, and Match sections at
  the end of sshd_config are commonplace. Both results are valid configuration
  files, so the check hostveil runs before writing accepted them and the fix
  reported success — while asking SSH for its effective settings still showed
  password authentication enabled. The re-check afterwards did still report
  the finding, so this was not a silent failure, but operators were told a fix
  had been applied, given a restore point for it, and left with passwords
  accepted and an edited Match block.

## [3.8.5](https://github.com/seolcu/hostveil/compare/v3.8.4...v3.8.5) (2026-07-29)

Four fixes for the same disagreement between what hostveil knew and what it
said: a fix that could not be undone, two domains that reported ground they
never covered, and a rule the code stated five times without enforcing once.

### Bug Fixes

* **history:** keep a fix rollbackable after it is applied
  ([#627](https://github.com/seolcu/hostveil/issues/627)). Checkpoint pruning
  runs on every save, so a `fix --all` that wrote more restore points than the
  store keeps deleted its own earliest ones — the fixes it applied first were
  unrollbackable the instant they were applied, and nothing said so. The cap
  named that as the thing that must never happen and then answered it by being
  a big enough number, which is a hope rather than a mechanism: adding
  `no-new-privileges` and setting a restart policy are both applied
  automatically and both apply to nearly every stock compose service, so a
  host with a hundred services reached the limit in one run. Nothing written
  in the last hour is discarded now, however much arrives at once, and the
  count still bounds a long-lived host's state directory.
* **check:** a home the agent scan cannot enter is not a home with nothing in
  it ([#628](https://github.com/seolcu/hostveil/issues/628)). Statting a
  directory needs only search permission on its parent, so someone else's
  home at mode 0700 passed the readability check and denied everything
  underneath it — the ordinary shape of a multi-user host scanned without
  root. The agent domain read that as an account with no runtime installed.
  It reported "no self-hosted agent runtime found" for an account it could not
  look inside and said nothing about sudo; worse, when another runtime was
  visible so the domain did run, the account it could not see never registered
  as a gap and the domain was scored as though it had covered ground it never
  saw. An unelevated scan now says which homes it could not read. Scans
  elevate themselves, so the usual path is unchanged.
* **check:** a file whose permissions cannot be read is not a file with good
  permissions ([#629](https://github.com/seolcu/hostveil/issues/629)). The
  file-permission domain skipped anything it could not examine, with a comment
  saying the skip was for files that are not installed. Absence and denial
  arrive identically, so a rule that could not run reported exactly like a rule
  that passed — on the domain whose whole job is noticing that a sensitive file
  is readable by the wrong people. The sharper half was the SSH host-key rule:
  expanding a wildcard reports a directory it cannot read as no matches at all,
  which is indistinguishable from a host that has no host keys, so an
  unreadable `/etc/ssh` silently cleared a high-severity check on private keys.
  This changes nothing on a standard host, where those paths are readable; it
  closes the case rather than a failure seen in the wild.
* **core:** never apply a command-running fix unattended
  ([#630](https://github.com/seolcu/hostveil/issues/630)). "Safe to apply
  automatically" rests on the change being reversible, and a fix that runs a
  command leaves no restore point — applying one in a batch means a command
  run as root with no way to undo it through hostveil. The code states that
  rule five times over while deciding what to offer, and it was held up
  entirely by each detection domain choosing to ask for confirmation by hand.
  Enabling automatic security updates is where that showed: its remediation is
  a single action, which is all the shape rule means, and the only thing
  between "fix everything safe" and `apt-get install` was the updates domain
  independently asking for review. Now anything that runs a command asks,
  whatever the domain declared. Nothing in this release changes what any
  existing finding offers.

## [3.8.4](https://github.com/seolcu/hostveil/compare/v3.8.3...v3.8.4) (2026-07-29)

One fix, for a scan that could not tell you everything it had failed to look
at.

### Bug Fixes

* **check:** report every coverage gap, not just the first
  ([#625](https://github.com/seolcu/hostveil/issues/625)). A domain can have
  more than one blind spot, and both container checkers decided what to
  report at the moment a gap was found — so whichever one lost the race was
  discarded, from the message shown in every interface and from the counters
  beside it. The CVE domain mentioned a compose file it could not parse only
  when no image had also failed to scan; hit both, as a host with one broken
  stack and one unreachable registry does, and the unparsed project vanished
  while its images went unexamined and the domain read "covered 1 of 2". The
  branch that does count it explains in its own comment why that matters: the
  images are absent from the attempted count, so without it the axis scores
  as though they were not on the host. The compose domain lost the same file
  the mirror way, reporting it only when container enumeration had succeeded.
  Both now build the result through a ledger that records every success and
  every gap and decides nothing until the end, so a second blind spot can
  only add to the first. Separately, the coverage fraction is printed only
  when something countable actually went unexamined — a gap with no unit of
  its own, such as being unable to list the containers started outside
  Compose, left the two numbers equal and told operators "audited compose
  projects only (covered 1 of 1)", which claims partial and complete coverage
  in the same sentence.

## [3.8.3](https://github.com/seolcu/hostveil/compare/v3.8.2...v3.8.3) (2026-07-29)

Two fixes for hosts and operators that are not ASCII, and one for a record
that could describe work nobody did.

### Bug Fixes

* **ui:** measure text in display columns, not bytes or runes
  ([#621](https://github.com/seolcu/hostveil/issues/621)). Three notions of
  "how wide is this" were in use at once: the padding function counted
  display columns, truncation counted runes, and wrapping — in the TUI and
  again in the CLI renderer — counted bytes. For ASCII all three agree, which
  is why nobody noticed. For anything else they diverge in opposite
  directions, and against Hangul, where one character is three bytes, one
  rune and two columns, wrapping at a width of 40 produced lines 24 columns
  wide while truncating to a 20-column budget produced 34. The second is the
  damaging one: truncation exists to make a cell fit the space computed for
  it, and the padding beside it measured the same cell differently, so rows
  ran past the edge of the terminal. This reaches ordinary hosts through
  compose service names, file paths, and `explain --ai`, which renders
  whatever the local model wrote. The interesting part of the fix is the
  width table: the obvious library call picks one from `LANG` and `LC_ALL` at
  startup, and under a Korean locale it calls `…`, `→`, `±` and `·` two
  columns wide — all four of which hostveil draws — so the same binary would
  have laid out screens differently for operators in different countries.
  An explicit table is pinned instead, and a test asserts it agrees with the
  one the terminal layer already uses.
* **core:** plan a mode change once per apply, not twice
  ([#622](https://github.com/seolcu/hostveil/issues/622)). Applying a
  permission fix planned the changes, then rendered its summary by planning
  them a second time. The paths it actually changed, and the modes it saved
  for rollback, came from the first pass; the summary stored in the
  checkpoint came from the second. A file altered between the two left the
  checkpoint describing a set that was never applied — rollback still worked,
  since the restore data came from the first pass, but the record of what
  happened did not match what happened. The summary is now rendered from the
  plan being executed. Its table was also aligned by byte count, so a single
  non-ASCII path threw every arrow in it out of line.

## [3.8.2](https://github.com/seolcu/hostveil/compare/v3.8.1...v3.8.2) (2026-07-29)

Two things the tool knew and did not say, and one it could not have said
because it would have crashed first.

### Bug Fixes

* **model:** render the batch outcome once instead of four times
  ([#618](https://github.com/seolcu/hostveil/issues/618)). Applying several
  fixes at once produces four facts — how many were applied, skipped, failed,
  and whether the run was cut short — and four surfaces described them in
  their own words. Two of the four dropped something that matters, both in
  the dashboard, both for the same engine response. The batch button never
  mentioned an interruption, which is the one outcome that flag exists to
  make visible: a batch stopped partway read exactly like one that finished,
  while the fixes that *did* land sat on the host with checkpoints waiting in
  History and nothing on screen suggesting there was anything to go back for.
  The fix-all button had the opposite hole — it reported neither skipped nor
  failed, so a fix that errored was invisible: the score moved, no reason was
  given, and the error had been in the response the whole time. The sentence
  is now rendered once by the engine and shown by all three interfaces. It
  stops short of saying *where* to look, because "press h" and `hostveil
  history` are directions to a place only one interface has; each appends its
  own. The CLI keeps its per-failure detail and its exit code, and now names
  the skipped count outside the interrupted case as well.
* **core:** check a fix's shape before offering it, not while applying it
  ([#619](https://github.com/seolcu/hostveil/issues/619)). Every fix declares
  a kind, and the kind is a claim about shape: Auto means exactly one
  mechanical action, Review means two or more real alternatives, an edit
  carries the pure function that produces the new bytes. A validator for all
  of that existed and ran only in one package's tests, against the sample
  findings those tests construct — its own comment said it "can gate
  registration", and it gated nothing. For any other finding the contract was
  unchecked, and an unchecked contract here is not a lint failure: a fix
  registered without its transform function was classified as fixable, drew a
  button in all three interfaces, and dereferenced a nil pointer the moment
  anyone previewed or applied it. `hostveil serve` runs as root. The engine
  now validates every fix as it resolves it, and one whose shape contradicts
  its kind is demoted to Manual — the same answer already given when no fix
  is registered, and the same promise the rest of the engine keeps: an
  interface never offers a button that leads nowhere. No fix that ships today
  was affected; what changed is that the guarantee now covers every finding
  rather than the sampled ones.

## [3.8.1](https://github.com/seolcu/hostveil/compare/v3.8.0...v3.8.1) (2026-07-29)

One false Critical, on hosts whose distribution keeps `nologin` somewhere
other than Debian's or Fedora's path.

3.8.0 was about a table written twice. This is the same fault a layer down
and with the copies further apart: two domains asked whether an account can
log in, and only one of them answered portably. The one that did not was the
one gating a Critical.

**If you run Arch or NixOS, your account-hygiene score should improve** —
because it was wrong, not because anything on your host changed.

### Bug Fixes

* **check:** recognise nologin shells wherever the distribution keeps them
  ([#615](https://github.com/seolcu/hostveil/issues/615)). The account domain
  decided whether an account could log in by matching its shell against a
  fixed list of six full paths — Debian's `/usr/sbin/nologin`, Fedora's
  `/sbin/nologin`, and four more. A distribution that keeps the same program
  elsewhere was not on it: Arch's `/usr/bin/nologin`, NixOS's under
  `/run/current-system/sw/bin`, anything hand-built under `/usr/local`. On
  those hosts every service account read as an ordinary login shell, so
  `accounts.emptypassword` reported "Login account with an empty password"
  for an account with no way in, at Critical, and took the axis down with it.
  The Docker daemon domain asks the same question of docker-group members —
  to separate an administrator who chose this from a credential nobody
  watches — and had already got it right by matching the path's suffix. Both
  now call one predicate that matches the program's base name, because the
  path is not portable and the name is. Two narrowings follow, each removing
  a false report rather than adding a true one: the empty-password finding
  stops firing on non-login accounts on those distributions, and a
  docker-group member whose shell is `/bin/true` is now correctly read as a
  service identity — a shell that exits successfully and immediately ends a
  session as firmly as one that fails.

The release also retires the last hand-written copy of the domain list, a
regex in the test that requires every emitted finding to be documented
([#616](https://github.com/seolcu/hostveil/issues/616)). It changes no
behaviour, but it was the twelfth table keyed by `model.Source` and the only
one 3.8.0 left standing.

## [3.8.0](https://github.com/seolcu/hostveil/compare/v3.7.0...v3.8.0) (2026-07-29)

This release adds the eleventh domain and then, unintentionally, tests the
lesson of the last one.

The new domain is the Docker daemon itself. hostveil already judged what a
service declares and what its images contain, and looked straight past the
process underneath that holds root — so a daemon listening on TCP without TLS
client verification, which is unauthenticated root for anyone who can reach
the port, was invisible.

3.7.0 was largely about interfaces that had fallen behind the engine, and its
headline fix was generating the dashboard's domain table from `model.AllSources`
so a hand-written copy could not go stale again. That fix held for the table it
covered. Twenty lines away in the same file sat a second label table, keyed by
axis ID, which had gone two domains stale without tripping anything — and the
comment beside the generated one explained at length why the remaining copies
were safe to leave. They were not. The conclusion this time is not to write the
tables more carefully but to stop having them: a domain is now one row, and
everything else — its name, its label, its scoring axis, the copies the browser
needs — is projected from it.

**Nothing about your score or your snapshots changes.** The domain enums are
serialized as bare integers into scan history, and the collapse was verified
against a capture of every value before and after.

### Features

* **check:** audit the Docker daemon itself
  ([#609](https://github.com/seolcu/hostveil/issues/609)). Seven rules over a
  new `dockerd` domain, scored on its own axis. No existing domain could have
  caught these, and not by oversight: the port table cannot judge 2375 because
  the number alone does not say whether TLS verification is in force, the
  accounts domain cannot ask whether Docker is even installed, and the file
  permissions domain refuses any path that is not a regular file or directory —
  a socket is neither. The hard part was deciding what to believe, since
  Docker's configuration lives in `daemon.json`, in flags on the unit, and in
  the running daemon, and after an edit without a restart those disagree. Each
  rule names one source and says why: `docker info` for effective daemon state,
  because reading the file would report the operator's intention as though it
  were the machine's behaviour; `daemon.json` unioned with the unit's
  `ExecStart` for socket and TLS settings, because `docker info` reports
  neither; and `ss` as evidence only.
* **demo:** expose the Docker daemon and seed the docker group
  ([#612](https://github.com/seolcu/hostveil/issues/612)). Without it the new
  domain lands with three of its seven rules unreachable in the one place this
  project can show a finding against a real daemon. Both socket findings are
  seeded through systemd drop-ins rather than `daemon.json` or `chmod`, because
  neither alternative survives: dockerd refuses to start when `hosts` and `-H`
  are both set, and a `chmod` on the socket is gone before hostveil looks,
  since dockerd recreates it at every start. The drop-in is also the
  misconfiguration operators actually make.

### Bug Fixes

* **model:** single-source the enum tables and the drift they hid
  ([#613](https://github.com/seolcu/hostveil/issues/613)). `model.Source` was
  described by six parallel tables — the const block, `String()`, `Label()`,
  the hand-maintained upper bound in `Valid()`, `AllSources()`, and `axisDefs`
  in another file — and three more enums had three to five each. Each is now
  one row, and `Valid()` became table membership, so the bound whose omission
  silently dropped a whole domain's findings can no longer be forgotten. Three
  user-visible consequences came out of the collapse. The dashboard's newest
  two axes render **"Kernel" and "Dockerd"** instead of long scoring labels
  truncated inside a narrow column. The CLI's score colour had **three bands
  where the other two interfaces had four**, so a host scoring 10 and a host
  scoring 40 printed identically — the lower half of that range being where the
  host is on fire. And the TUI and the dashboard both said **"No problems
  found. Clean."** unconditionally, so a host whose every checker had failed
  read as spotless in two interfaces out of three; only the CLI had ever
  refused, because the predicate lived in the CLI's own renderer. The guards
  moved with it: the coverage tests now walk the constant range rather than
  `AllSources()`, since a constant declared without a row never appears in the
  projection and every test that iterates it would pass vacuously — in the
  direction that reports the missing domain as fine.

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
* **core:** re-check the finding after applying its fix
  ([#607](https://github.com/seolcu/hostveil/issues/607)). "hostveil wrote
  the file" and "the finding is gone" are different claims, and only the
  first was ever established — `markFixed` set the flag the moment an apply
  returned, and the score moved on that. A fix now re-runs its own domain
  and says which of the three it got: gone, still reported, or unconfirmed.
  The result deliberately does not decide whether the finding counts as
  fixed. A persisted kernel drop-in is correct and complete while the
  running kernel still reports the old value until the next boot, so a
  checker that still sees it is not evidence of failure — and a re-check
  that was skipped or degraded has established nothing in either direction.

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
