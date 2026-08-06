# Changelog

## Unreleased

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
