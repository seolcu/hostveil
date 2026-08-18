package fix

// Default returns a Registry with every built-in fix registered. The
// engine treats this registry as the authority for which findings are
// Auto/Review; anything without a registered fix is Manual.
//
// # Choosing Auto, Review, or Manual
//
// A finding is Auto only when applying it unattended, as part of "fix all
// safe", is defensible without the user having looked at it. That requires
// all three of:
//
//  1. Reversible. The action leaves a checkpoint that restores exactly what
//     it changed — an edit stores the original bytes, a mode change stores
//     the original permission bits. Exec actions are never Auto, and the
//     reason is that nothing about them can be recorded to undo, not that
//     they fail to be file edits: applyExec has no checkpoint at all.
//  2. Recoverable in practice, not just on disk. If the change is wrong,
//     the user must still be able to reach the machine to roll it back.
//     Anything that can sever the operator's own access — SSH
//     authentication, firewall policy — fails this even though the file
//     edit itself is perfectly reversible.
//  3. Unambiguous. Exactly one correct remediation, and applying it cannot
//     break a legitimate configuration.
//
// Review means the fix is real and hostveil can apply it, but the user
// should see it first. Use it when the action is not file-backed, when it
// could cut off access to the host, or when there are several defensible
// remediations to pick between.
//
// Manual means there is no action hostveil can safely take. Prefer it over
// a fix that is technically applicable but likely to break things.
//
// The checker's declared kind and the registered fix's kind are resolved
// by Engine.classify, which takes whichever demands more human
// involvement. A fix registered here as Auto is a statement about its
// shape — one mechanical action — and does not override a checker that
// asked for Review.
//
// firewall.inactive was on the list below until the checker started
// recording the port sshd is actually listening on. The refusal was never
// about the commands — it was that hostveil could not know which port to keep
// open, and a firewall enabled without that answer locks the operator out with
// no checkpoint to undo it. With the port in evidence the fix allows it first
// and enables the policy second, as two commands of one action, and stays
// Review: the change cannot be rolled back and it takes every other inbound
// port with it, both of which an operator should decide rather than discover.
//
// # Findings deliberately left without a fix
//
// These are fixable in principle and are demoted to Manual on purpose.
// TestKnownUnregisteredFindings pins each one, so registering a fix means
// deleting an assertion and arguing with the reason.
//
//   - firewall.docker-bypass — the two remediations are unrelated and only
//     the operator can choose. Republishing the port to loopback means
//     editing whichever Compose file or `docker run` invocation started the
//     container, then recreating it, which takes the service down and is not
//     a file edit hostveil can locate from the finding. Installing the
//     ufw-docker rules means appending to /etc/ufw/after.rules and reloading
//     ufw — firewall policy, so it fails the same recoverability criterion as
//     firewall.inactive.
//   - updates.reboot-required — the remediation is rebooting the host, which
//     is an exec action with no checkpoint and takes every service on the box
//     down with it. Only the operator knows when that downtime is acceptable,
//     and a tool that reboots a server as part of "fix all safe" would be
//     indefensible whatever the finding said.
//   - updates.pending-security — `apt upgrade` is exec, so never Auto, and it
//     is also unbounded: it can pull in a new kernel, restart services, and
//     prompt about modified config files. Nothing about that is reversible
//     from a checkpoint, and a package upgrade that breaks a service leaves
//     the operator worse off than the pending patch did.
//   - fileperms.owner — the remediation is `chown root:root`, and hostveil
//     cannot undo it. A checkpoint records a file's contents and its mode
//     and has nowhere to put its previous owner, so this would be the only
//     fix in the tool that changes something a rollback cannot put back.
//     The right group is not guessable either: /etc/shadow is root:shadow
//     on Debian and root:root on others, so a fix would have to pick one
//     and would be wrong on the other half of hosts. And ownership landing
//     on the wrong account is usually a symptom — a restore run as the
//     wrong user, an archive extracted with its own uids — where chowning
//     the files hostveil happens to know about fixes the visible part and
//     leaves the rest. Revisit if BackedFile ever records uid/gid.
//   - firewall.default-allow — the remediation is flipping the default
//     inbound policy to deny, which is firewall.inactive's remediation
//     applied to a firewall that happens to already be running, and it is
//     declined for firewall.inactive's reason. The new policy takes effect
//     the moment it is set, on every connection no rule already allows —
//     including the SSH session the operator is issuing it from. Exec fixes
//     have no checkpoint, so a lockout has no undo. The how-to-fix says to
//     allow SSH first, which is advice a person can follow in order and a
//     fix cannot: hostveil does not know which port that session is on.
//   - ports.exposed-datastore, ports.exposed-admin — these describe
//     natively-installed daemons, not containers. Binding one to loopback
//     means editing redis.conf's `bind`, or postgresql.conf's
//     `listen_addresses` plus a matching pg_hba.conf rule, or mongod.conf's
//     `net.bindIp` — a different file, syntax, and distro-dependent path
//     per datastore, none of which the finding carries. Guessing a config
//     path means writing a transformed file somewhere that is not the live
//     config. The container-managed subset is already covered by ds018/019.
//   - compose.ds016 — mounting the Docker socket is root-equivalent, and
//     the only honest remediation is deleting the mount, which breaks
//     Portainer, Traefik, and Watchtower, all of which legitimately need
//     it. Adding :ro is not an alternative: the socket is an HTTP API, so a
//     read-only mount still permits container creation and host mounts. A
//     fix that improves the score while changing nothing is worse than no
//     fix.
//   - cve.<vulnerability-id> — no longer emitted at all, and must never
//     become fixable if it returns. Trivy's fixed_version is the OS package
//     version inside the image (`3.0.11-1~deb12u2`), not an image tag.
//     There is no mapping from one to the other; treating them as
//     interchangeable is what issue #473 was. Nothing hostveil can compute
//     turns "openssl must reach 3.0.11-1~deb12u2" into an image reference,
//     so a per-CVE fix would have to invent one. That is also why the
//     checker stopped emitting one finding per vulnerability: a finding is
//     a thing you can act on, and every CVE in an image shares the single
//     remediation that cve.outdated-image now carries. The registry matches
//     that ID exactly, so no cve.* glob can sweep the old shape back in.
//   - compose.ds009 — the only remediation is setting `user:`, and the
//     finding carries no evidence about which UID the image supports.
//     Images that drop privileges in their own entrypoint fail to start
//     when a UID is forced on them (postgres needs root to chown its data
//     directory; nginx needs root to bind :80 before demoting itself), and
//     an image with a baked-in USER already has the right answer that an
//     override would clobber. Every candidate UID is a guess, so this is
//     not even a Review: there is no pair of defensible alternatives, only
//     a pair of equally arbitrary ones, and offering 1000:1000 next to
//     65534:65534 would dress a coin flip as a choice.
//   - compose.ds017 — adding `:ro` is the one mechanical remediation, and
//     for a service that legitimately writes to the mount it breaks the
//     service outright. The other remediation the finding names, mounting
//     a narrower subdirectory, requires knowing which paths the service
//     actually touches, which a static audit cannot learn. That leaves one
//     alternative where Review requires two. Revisit if the checker can
//     ever tell a written mount from a read one.
//   - compose.ds001, compose.ds005, compose.dr001 — all three are
//     removal-shaped: delete `privileged: true`, drop a capability from
//     cap_add, delete `network_mode: host`. Each removes something the
//     author added deliberately, and hostveil cannot tell a needless one
//     from a load-bearing one. dr001 is the clearest: removing host
//     networking without knowing which ports to publish in its place
//     leaves the service unreachable, and the finding does not carry them.
//   - compose.ds020, compose.ds021 — removal-shaped like the three above:
//     delete `pid: host`, delete `ipc: host`. Both are settings nobody types
//     by accident — a monitoring agent needs the host PID namespace, a pair
//     of processes sharing memory needs the IPC one — and hostveil cannot
//     tell that deployment from a cargo-culted one. Deleting the line breaks
//     the legitimate case silently: the service starts fine and stops seeing
//     what it existed to see.
//   - compose.ds022 — the one mechanical remediation, `read_only: true`,
//     breaks any image that writes inside its own filesystem, which is most
//     of them (/tmp, /run, log directories). Making it work needs tmpfs
//     mounts for exactly the paths the service writes, and a static audit
//     cannot learn which paths those are. A fix that takes the service down
//     to improve the score is worse than no fix.
//   - compose.dr005 — moving a value into an env_file is a two-file change
//     where Action carries one Path, and a move that does not delete the
//     original improves nothing. More to the point, by the time the secret
//     is found it has already leaked into backups and git history, so the
//     real remediation is rotating it, which hostveil cannot do.
//   - agent.gateway-exposed — rebinding a gateway to loopback can cut an
//     operator off from the agent they administer remotely, which is
//     firewall.inactive's recoverability criterion. The other agent config
//     keys are fixable now; see "The agent config keys" below for what
//     changed and for the two that are declined for their own reasons.
//   - compose.ds012 — the remediation is a healthcheck, and the right one
//     depends entirely on what the service exposes: an HTTP path, a CLI
//     probe, a port to open. A static audit cannot learn any of them, and a
//     guessed healthcheck is worse than none — a probe that does not match
//     the app marks a working container unhealthy, and anything waiting on
//     `condition: service_healthy` then never starts. The finding's own
//     how-to-fix says this cannot be filled in automatically; this is the
//     registry agreeing with it.
//   - compose.dr004 — the finding is not that a value is wrong but that
//     credentials live in an env_file, and the remediation is to check that
//     file's permissions and that it is out of version control and backups.
//     One of those is a fact about a path the finding does not carry, and
//     the other two are about systems hostveil cannot see. There is nothing
//     in the compose file to edit.
//   - ports.exposed — the aggregate finding, which fires only when no
//     firewall is active at all. Its remediation is firewall.inactive's,
//     and it is declined for firewall.inactive's reason: enabling
//     default-deny on a box reached over SSH can lock the operator out
//     irrecoverably, and exec fixes have no checkpoint. Fixing the firewall
//     resolves this finding as a side effect, which is the right order.
//   - accounts.uid0 — the remediation is deleting an account or changing
//     its UID, and hostveil cannot tell a backdoor from a deliberate
//     second root that a recovery procedure depends on. `userdel` is not
//     reversible from a checkpoint at all: the account entry, its group,
//     and its mail spool go, and every file it owned is left orphaned by
//     UID with nothing recorded that could give it back. (It leaves the
//     home directory unless it is given -r, which is what the finding's
//     how-to-fix recommends — this used to say otherwise.) Changing the
//     UID instead orphans those same files, which the finding does not
//     enumerate and could not restore.
//   - accounts.emptypassword — `passwd -l` is a real, mechanical
//     remediation and it is deliberately not registered. It is exec, so
//     never Auto; and it fails the recoverability test in the way that
//     matters most, because the account it locks may be the only one the
//     operator can reach the machine with. An empty password on a console-
//     only account is a different situation from one on the account you
//     SSH in as, and /etc/shadow does not say which this is. Setting a
//     password instead cannot be done unattended by definition — hostveil
//     would have to invent one, and then it would know it.
//   - proxy.traefik-api-insecure — the remediation is deleting one flag, and
//     it is exec-shaped rather than edit-shaped in the way that matters:
//     Traefik reads it at start, so the change is not in force until the
//     container is recreated, and recreating the container that fronts every
//     other service on the host is not a thing to do while nobody is
//     watching. The honest fix is also not just a deletion — an operator who
//     wanted the dashboard still wants it, through a router with
//     authentication, and hostveil cannot invent which hostname or which
//     middleware. Deleting the flag alone takes the dashboard away without
//     saying so.
//   - proxy.tls-deprecated-protocols — the line to write is unambiguous and
//     the file to write it in is not. nginx resolves ssl_protocols by the
//     usual inheritance: a value in `http` covers every server that does not
//     set its own, and a server block that sets one wins for that vhost.
//     hostveil sees which files name the directive, not which block each
//     occurrence sits in, so it cannot tell an edit that fixes the host from
//     one that fixes a single vhost and leaves the rest — and the finding
//     would clear either way. This is persistSysctl's rule about writing the
//     file that does not decide the value, in a configuration language whose
//     precedence hostveil does not model.
//   - proxy.directory-listing — the same shape and a sharper version of it:
//     `autoindex on` is sometimes deliberate for one location, and the
//     remediation is to narrow it rather than to remove it. A fix that
//     deleted the directive would break a directory somebody meant to be
//     browsable, and one that turned it off at the server level would change
//     a vhost hostveil never looked inside.
//   - accounts.sudo-nopasswd — removing NOPASSWD is one line and hostveil
//     will not touch it, for the reason that makes this finding common in
//     the first place. Cloud and VM images ship the rule *because* the
//     account they create has no password; take the rule away and that
//     account cannot use sudo at all, so the fix that closes the hole also
//     removes the operator's only route to root. The edit reverts cleanly
//     and that is not the test — "recoverable in practice" asks whether
//     they can still get in to revert it. hostveil cannot check the
//     precondition either: whether a usable password exists is a question
//     about a hash in /etc/shadow, and a hash being present does not mean
//     anybody knows what it is. So the finding names the accounts, and the
//     how-to-fix says to set the password and confirm it in a second
//     session before removing the rule.
//
// (sysctl.* was in this list and is not any more; see below.)
//
// # Auto fixes that touch a user's home
//
// agent.config-perms and agent.secret-exposed are the first Auto fixes
// aimed outside /etc: they chmod paths under ~/.openclaw and ~/.hermes,
// which means root running `fix --all` tightens another user's files.
//
// That is deliberate and meets the standard. tighten is subtractive, so it
// only ever removes access; SaveModes checkpoints the prior mode, so it
// rolls back exactly; and no permission on an agent's own state directory
// can sever the operator's access to the host the way an SSH or firewall
// edit can. The values are also not guesses — each target's mode is the
// baseline the runtime's own hardening guide specifies.
//
// The one deployment it could disrupt is an agent daemon running as a
// different user and reading the config through group permissions. Upstream
// ships these paths at 0600/0700, so that arrangement is a deviation rather
// than a design, and the finding's how-to-fix names it explicitly.
//
// A path under a home carries one more obligation that /etc never did: the
// account that owns it can shape it, so "safe to apply unattended" must hold
// against an adversarial layout, not just a mistaken one. Every step from
// detection to apply therefore refuses to follow a symlink — the checker
// Lstats and skips non-regular files, planModes re-vets the type, and the
// chmod itself goes through a descriptor opened O_NOFOLLOW — because a
// symlink at ~/.openclaw/openclaw.json pointing at /etc/passwd would
// otherwise turn `fix --all` into root tightening the password database off
// the host. Any future Auto fix whose target another account can influence
// owes the same discipline.
//
// That obligation came due immediately: the agent config-key fixes below are
// the first edits — writes, not chmods — aimed at a path inside a home, and
// they carry Action.NoFollow so the read refuses a symlink the way the chmod
// already did. The write never needed it, because WriteFileAtomic renames
// over a link rather than through it; the read did, because a preview
// renders the file it read into a diff, and root reading an arbitrary file
// for somebody is the whole of the exposure.
//
// # The agent config keys, and what a JSON5 editor did and did not settle
//
// Seven agent.* findings were declined together above, for one shared
// reason: they all reduce to editing a key in OpenClaw's config, that config
// is JSON5 carrying the operator's own comments and trailing commas, and
// re-encoding it through encoding/json deletes every one of them. There was
// no editor that could make a one-key change without doing that damage.
//
// internal/json5 is that editor, built the way internal/compose/edit.go is —
// locate the value's bytes, replace exactly those, leave the rest alone —
// with one difference worth knowing. compose can fall back to re-encoding
// the whole document through yaml.v3 when its text surgery is not provably
// right, because yaml.v3 keeps comments. There is no such fallback here, so
// a rendering that cannot be proven correct is an error and the fix is not
// offered. That is also what stands in for a VerifyCmd: neither runtime
// ships a config validator, and `Bytes` re-parses its own output and refuses
// it unless the tree matches the original with exactly the named keys
// changed.
//
// Four findings became fixable, and the shape follows from the table rather
// than from a decision made here. internal/check/agent's DangerRule now
// carries the safe values for each key, and the checker reads the finding's
// remediation kind off them: one safe value is Auto, two are Review.
// agent.exec-unrestricted is the Review case — tools.exec.security is deny
// or ask, and which is right depends on whether the agent is meant to run
// commands at all, so they are independent alternatives rather than a
// sequence. agent.elevated-enabled, agent.control-ui-insecure and
// agent.ssrf-private-network each have exactly one correct value, are one
// mechanical file edit, and cannot sever anyone's access to the host.
//
// Two stayed declined, and the JSON5 editor is why the real reasons are now
// visible rather than hidden behind the shared one:
//
//   - agent.sandbox-off — hostveil knows `off` is wrong and does not know
//     what turns the sandbox on. No value in this repository, in the rule
//     table or in the finding's own how-to-fix, names a mode. Writing a
//     guessed enum into somebody's agent config is the invented mapping the
//     per-CVE fixes are declined for, arriving by another route, so the rule
//     carries no safe value and the finding stays Manual.
//   - agent.auth-disabled — same shape, plus one thing the editor cannot
//     express. OpenClaw fails closed when gateway.auth.mode is unset, so the
//     safe posture is an *absent* key, and internal/json5 replaces values
//     and deliberately neither creates nor deletes them. Setting some other
//     mode instead would require knowing which modes exist.
//
// Hermes has no danger rules at all, and if it gains some they are not
// covered by any of this: its bind and auth may come from the config, from
// ~/.hermes/.env, from a systemd unit, or from a docker -e flag, and the
// finding cannot tell which is in force, so an edit could silently change
// nothing. The checker refuses to emit safe values for a non-JSON5 runtime
// for exactly that reason.
//
// # The kernel-hardening fixes, and why they stopped being declined
//
// Every sysctl.* finding was on the list above, for one shared reason:
// persisting a value means writing an /etc/sysctl.d drop-in that does not
// exist — and if it did exist the value would already be set, so the
// finding would not have fired — while edit actions could only modify a
// file already on disk. That left one remediation, `sysctl --system`, with
// no partner, and "write the drop-in, then apply it" is sequential steps,
// exactly what Review's independent-alternatives shape forbids.
//
// Action.CreateIfMissing removes the blocker, and what it reveals is that
// there were two independent alternatives all along:
//
//   - write the drop-in — persistent, effective at the next boot;
//   - `sysctl -w` — effective now, gone at the next boot.
//
// Neither dominates. An operator hardening a box they are about to reboot
// wants the first; one who cannot restart a production host today wants
// the second now and the first later. That is a choice, not a sequence.
//
// They are Review and not Auto, and the reason is not the shape. Writing
// the drop-in is one mechanical, reversible file edit and would otherwise
// qualify — but it is not unambiguous. rp_filter is 1 on a single-homed
// server and 2 on a VPN or multi-homed one; sysrq has a restricted-bitmask
// answer as legitimate as 0. hostveil audits only the unambiguous half of
// each and writes only what it audited, but the operator is the one who
// knows which host this is, so they see it first.
//
// One file per finding, never a shared 99-hostveil.conf. Independence is
// the whole point: applying the second fix must not have to read what the
// first wrote, and rolling one back must not take another's line with it.
//
// # The service-hardening domain, deliberately declined where runtime needs are unknown
//
// The same runtime-dependency rule covers systemd.private-devices,
// systemd.protect-kernel-tunables, systemd.protect-kernel-modules,
// systemd.protect-control-groups, systemd.protect-kernel-logs,
// systemd.protect-clock, systemd.restrict-suid-sgid,
// systemd.restrict-namespaces, systemd.lock-personality, and
// systemd.memory-deny-write-execute. Each can stop a legitimate service only
// when it next starts, and the effective property list cannot reveal that need.
//
// accounts.duplicate-uid requires migrating file ownership, while
// accounts.weak-password-hash requires a human-chosen credential. Compose
// rules compose.ds023, compose.ds024, and compose.ds026 remove deliberately
// selected isolation exceptions whose application requirements are unknown.
//
// The edit is trivial for all four: a drop-in at
// /etc/systemd/system/<unit>.d/50-hostveil.conf holding a [Service] section
// and one directive, created by CreateIfMissing, reversed by deleting the
// file. What is not trivial is knowing it is safe, and for three of them it
// is not knowable. systemd.protect-system breaks a service that writes under
// /usr; systemd.private-tmp breaks two services that hand each other files
// through /tmp; systemd.protect-home breaks anything whose data lives in a
// home directory, which on a self-hosted box is common. None of that is
// visible from the unit — it depends on what the program does — so no amount
// of reading gets hostveil to "unambiguous". Those three stay declined.
//
// Named one by one rather than as systemd.*, which is what this said while
// the domain was declined whole. A glob now would cover the one that is not.
//
// NoNewPrivileges is registered, and separating it from the other three is
// the whole of the change. It has no such blind spot: it closes the setuid
// path, and nothing about the unit hides whether a service deliberately
// escalates the way a unit hides which directories a program writes to. It is
// also the same protection the container domain fixes automatically under the
// same name.
//
// This paragraph used to argue the domain away whole, and two of its three
// legs were about the other three rules. The third was about shape: "a
// drop-in and a restart are not two alternatives, they are one procedure in
// two steps, and systemd has no equivalent of `sysctl -w`". That leg is gone.
// Action.TakesEffectOn is precisely the shape of "written now, in force when
// X happens", and every compose fix stands on it; the sentence predates it.
//
// What survives is the delayed failure: a service that does not come back is
// discovered at the next restart, which on a host like this can be the next
// reboot. That rules out Auto and it is exactly what Review is for. The
// checker declares Review, the registration here is one action — Auto's shape
// and nothing more — and resolvedKind shows the operator the more cautious of
// the two. firewall.inactive reaches the screen the same way.
//
// The re-check after applying it will still report the finding, and that is
// correct rather than a failure. This checker asks systemd for each unit's
// effective configuration, and systemd has not re-read the file; VerifyStillPresent
// says so in the sentence it was written for — "the change may not take
// effect until '<unit>' restarts". For the same reason the fix is absent from
// internal/fix/roundtrip_test.go: the loop needs a checker that reads what the
// fix wrote, and this one deliberately does not.
//
// # The Docker daemon domain, declined whole
//
// dockerd.* has no registered fix at all — not one finding, and not because
// nobody has looked. The two blockers that would ordinarily explain it are
// both gone, which is why the real reason has to be written down.
//
// Action.CreateIfMissing handles the absent /etc/docker/daemon.json, exactly
// as it does for the sysctl drop-in. And `dockerd --validate --config-file`
// is a genuine `sshd -t` analogue: it rejects malformed JSON and unknown
// directives, accepts an empty file — so runEditValidator's control run on the
// original passes for a create-if-missing action — and needs no running
// daemon. A VerifyCmd here would work.
//
// The reason is structural, and it is the one thing this domain does that
// no other does: the checker reads the daemon's *running* state, while a fix
// would edit a file the running daemon will not read again until it
// restarts. `systemctl restart docker` stops every container on the host.
//
// So an applied fix would write the file, take a checkpoint, mark the
// finding Fixed, and raise the score — while changing nothing an attacker
// can see. The next scan asks `docker info`, gets the same answer as before,
// and reports the finding again. A fix that improves the score without
// improving the host is the objection already recorded for compose.ds016,
// arriving by a different route.
//
// Both halves of that objection are now answered, and neither answer is what
// unblocks this domain — which is worth recording, because "the shared reason
// went away" reads like "these are registerable now" and they are not.
//
// The message was answered first: Action.TakesEffectOn and model.VerifyPending
// mean hostveil can write the file and say plainly that the change reaches the
// host at the next daemon restart, instead of re-checking `docker info` and
// calling the finding gone.
//
// The score is answered now too. model.Finding.Pending keeps a fix charged
// until it is in force, so an applied-and-waiting fix no longer moves the
// number — the objection this paragraph used to record, that registering these
// would improve the score without improving the host, no longer follows from
// registering them.
//
// What that leaves is one blocker doing nearly all the work, and it is the one
// that arrived last: daemon.json. internal/json5 replaces the value at a key
// path that ALREADY EXISTS and neither creates nor deletes, so it cannot add
// `"no-new-privileges": true` to a file that does not carry the key — which is
// every host that has not already set it, i.e. every host with this finding —
// and it cannot remove the `tcp://` endpoint the two API findings are about.
// Editing daemon.json any other way means re-encoding through encoding/json
// and reordering the operator's keys, which is precisely the damage
// internal/json5 was written to prevent. That covers five of the seven, and
// the remaining two never rested on the score at all: group-members is exec
// and may remove the operator's own account, and the API pair fails
// firewall.inactive's recoverability criterion whatever edits the file.
//
// dockerd.socket-world-writable is the one whose recorded reason genuinely
// falls, and it still is not a registration. Its objection was that the honest
// remediation is a unit drop-in "which needs a restart to apply", and that is
// now a thing a fix can say rather than a thing that stops it. Three pieces of
// new work stand where the old reason stood, none of them removed by this
// change: the checker declares RemediationManual, so resolvedKind floors it
// there whatever the registry offers; the dockerd checker does not read
// DropInPaths, so nothing here knows which drop-in wins for docker.socket, and
// writing 50-hostveil.conf without that would repeat exactly the failure
// persistSysctl exists to avoid; and restarting docker.socket under a running
// docker.service is not the clean operation it looks like.
//
// That middle one used to be true of the systemd domain as well, which made it
// an odd thing to decline dockerd over: systemd.no-new-privileges wrote
// 50-hostveil.conf with no resolution at all. It resolves now — the checker
// asks systemd which drop-ins it loaded and picks a name that sorts after all
// of them, or refuses when none would — so the reason is a statement about
// what the dockerd checker reads rather than about what this project is
// willing to do.
//
// One thing Pending does not do, so that nobody reads it as more than it is:
// it corrects the score between an apply and the next scan, and nothing more.
// A rescan builds findings from the checkers, so for a domain whose checker
// reads the artifact rather than the running state — compose above all — the
// scan after a fix still reports the finding gone while the container runs the
// old configuration. That gap is older than this and is what TakesEffectOn was
// introduced to describe rather than to close; it is why
// scripts/measure/run.sh has a separate phase for after the services are
// restarted. Closing it would mean the compose checker reading containers, and
// that is a different change.
//
// The asymmetry with SSH is what makes this consistent rather than
// arbitrary. The ssh checker reads sshd_config, which is the same artifact
// the ssh fix edits, so the Fixed mark is honest and the restart is a hint.
// Here the artifact and the oracle are two different objects, and only one
// of them is what the domain reports on.
//
// Each finding also has its own reason on top of that shared one:
//
//   - dockerd.api-unauthenticated and dockerd.api-tls-unverified — removing
//     the TCP endpoint severs the exact channel a remote operator may be
//     administering the host through: DOCKER_HOST, a Portainer agent, a CI
//     runner. That is firewall.inactive's recoverability criterion.
//   - dockerd.group-members — `gpasswd -d` is exec, so never Auto, and the
//     member it removes may be the operator's own account and the access
//     they administer the daemon with. That is accounts.emptypassword's
//     objection.
//   - dockerd.socket-world-writable — the only one of the seven that does not
//     touch daemon.json, and so the only one whose reason had to be rewritten
//     rather than re-pointed. The socket's mode is not durable state: dockerd
//     recreates the socket from the systemd docker.socket unit on every
//     start, so a chmod is undone at the next restart and the honest
//     remediation is a unit drop-in. "Which needs a restart to apply" used to
//     end that sentence and no longer ends anything — Action.TakesEffectOn
//     says exactly that. What stands in its place is precedence: systemd
//     merges drop-ins in lexical order and nothing here resolves which one
//     sets SocketMode, so hostveil would be writing a file it cannot show
//     wins. That is persistSysctl's rule, which this domain has not yet had
//     to face because it has never written anything. The checker also
//     declares RemediationManual, so resolvedKind floors it there until that
//     moves too.
//   - dockerd.live-restore — the one setting `systemctl reload docker` picks
//     up without bouncing containers, which is what makes it look fixable.
//     Its shape objection has weakened: "write it, then apply it" is one
//     action and a TakesEffectOn now, not two sequential steps pretending to
//     be alternatives. The editor is what stops it, as above.
//   - dockerd.no-new-privileges and dockerd.userns-remap — the shared reason
//     alone, which is now the editor. Both are also daemon defaults that take
//     effect only for containers started after a restart — describable, since
//     3.17 — and userns-remap additionally rewrites the ownership of every
//     bind mount on the host, which is not.
//
// # The one CVE finding that does have a fix
//
// cve.outdated-image, the per-image rollup, IS registered, because its
// remediation differs in kind from the per-CVE one rather than being a
// softer version of it. Re-pulling a mutable tag needs no version mapping
// at all — only the tag the user already chose — and it claims nothing
// about which CVEs the new image happens to fix. Its how-to-fix says only
// that it re-resolves the tag, which is the whole of what it can promise.
//
// It is declined for digest-pinned references, where a pull is a no-op by
// construction and the honest remediation, repinning to a newer digest,
// needs exactly the data the per-image report does not have. Digest-vs-tag
// is the only split drawn: every non-digest reference is a mutable pointer,
// and guessing which tags are "really" pinned from their spelling would be
// wrong for :2024-01-15 and :stable — and wrong in the direction that
// suppresses a real fix.
//
// Being exec, it is Review and can never be Auto, so "fix all safe" does
// not touch it. ApplyBatch excludes it twice over: not Auto, and more than
// one action.
//
// Its sibling cve.unpatched-image is Unavailable and has no fix by
// construction: it collects exactly the vulnerabilities nobody has
// published a fix for. It exists so that an image whose vulnerabilities are
// all unfixed still produces a finding rather than vanishing into a clean
// report.
func Default() *Registry {
	r := NewRegistry()
	registerCompose(r)
	registerFilePerms(r)
	registerSSH(r)
	registerUpdates(r)
	registerFirewall(r)
	registerAgent(r)
	registerSysctl(r)
	registerSystemd(r)
	return r
}
