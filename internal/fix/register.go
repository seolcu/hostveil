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
// firewall.default-allow reuses the same evidence and the same fix, applied
// to a firewall that happens to already be running: allow SSH first, then
// flip the default inbound policy from accept to deny. It was declined for
// exactly firewall.inactive's original reason — no known SSH port — and that
// reason no longer holds here either. Both stay restricted to ufw; firewalld's
// target flip has no registered fix yet.
//
// # Risky fixes, offered one at a time
//
// Twelve container findings used to sit in the register below, every one for
// the same reason: the remediation removes or restricts something the author
// may have set on purpose — privileged mode, a capability, host networking,
// a Docker socket mount — and hostveil cannot tell a load-bearing setting
// from a cargo-culted one. That reason is still true. What it no longer
// decides is whether there is a button. A fix that might break a deployment
// is Review rather than Auto, carries a Warning that names what it might
// break, and is IndividualOnly so no batch — `fix --all --review` included —
// applies it on nobody's behalf. Each is a file edit with a checkpoint, so
// the operator who presses it and finds the service broken rolls it back
// exactly. The builders and their warnings are in compose_risky.go.
//
// The same reasoning took three host findings off the register, in
// host_risky.go, all exec and so with no checkpoint: a reboot to load
// installed updates, scheduled a minute out so it can be cancelled; locking
// and expiring a second UID-0 account, with deletion as the irreversible
// alternative; and expiring a password stored under a weak hash, which is
// the one thing hostveil can do without inventing the credential. The UID-0
// checker learned to stop reporting an account that is locked and expired,
// because that is an account nobody can log in as.
//
// network_risky.go took four more. firewall.docker-bypass installs the
// ufw-docker block in after.rules and reloads ufw through AfterWrite, which
// restores the file and reloads again if ufw refuses it. compose.dr004 and
// kube.token-readable are subtractive chmods with checkpoints; the token's
// Warning says it still needs rotating. kube.kubeconfig-readable is the same
// chmod, durable on k0s and lasting until the next start on k3s, which its
// Warning says along with where the persistent setting lives.
//
// # Findings deliberately left without a fix
//
// These are fixable in principle and are demoted to Manual on purpose.
// TestKnownUnregisteredFindings pins each one, so registering a fix means
// deleting an assertion and arguing with the reason.
//
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
//   - ports.exposed-datastore, ports.exposed-admin — these describe
//     natively-installed daemons, not containers. Binding one to loopback
//     means editing redis.conf's `bind`, or postgresql.conf's
//     `listen_addresses` plus a matching pg_hba.conf rule, or mongod.conf's
//     `net.bindIp` — a different file, syntax, and distro-dependent path
//     per datastore, none of which the finding carries. Guessing a config
//     path means writing a transformed file somewhere that is not the live
//     config. The container-managed subset is already covered by ds018/019.
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
//   - ports.exposed — the aggregate finding, which fires only when no
//     firewall is active at all. Its remediation is firewall.inactive's,
//     and it is declined for firewall.inactive's reason: enabling
//     default-deny on a box reached over SSH can lock the operator out
//     irrecoverably, and exec fixes have no checkpoint. Fixing the firewall
//     resolves this finding as a side effect, which is the right order.
//   - accounts.duplicate-uid — the remediation is giving one of the
//     accounts a new UID, which means re-owning every file it holds across
//     the filesystem. That is not one action and not one checkpoint, and a
//     partial migration leaves two accounts each owning half of what was
//     theirs.
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
//   - proxy.admin-api-exposed — the edit is small and the outcome is not
//     knowable from here. Moving Caddy's admin API back to loopback, or
//     turning it off, cuts whatever was calling it: a deploy script, a
//     configuration manager, a sidecar that reloads certificates. Nothing in
//     a Caddyfile records who that is, and a proxy that stops accepting its
//     own updates goes on serving until something needs to change and then
//     cannot. For a container the setting is as often CADDY_ADMIN in the
//     Compose file as an option in the Caddyfile, and it is not in force
//     until the container fronting every other service is recreated — the
//     proxy.traefik-api-insecure argument again.
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
//   - proxmox.webui-open — the edit is a few lines in /etc/default/pveproxy
//     and the values are the operator's alone: which network is the
//     management network is not in any file hostveil reads, and a guess that
//     leaves out the address the operator is using locks them out of the
//     hypervisor's interface on the next restart. LISTEN_IP, the other half,
//     breaks clusters whose nodes reach each other across subnets, which
//     upstream warns about in the same breath as documenting it.
//   - proxmox.root-no-tfa — enrolling a second factor is a person holding a
//     device, and writing tfa.cfg on their behalf would be hostveil inventing
//     a credential.
//   - proxmox.enterprise-repo-unsubscribed — two changes in sequence (turn
//     the enterprise source off, add the no-subscription one for the right
//     release), where Review means alternatives, and the first alone leaves
//     the host with no Proxmox source at all, which is worse than the finding.
//     A subscription key is the other remedy and is not hostveil's to enter.
//   - kube.anonymous-auth and kube.secrets-unencrypted — both are a change
//     to how the control plane starts, in whichever layer set them, and
//     both need a restart of the node every workload runs on; encryption
//     also needs existing Secrets rewritten afterwards.
//   - accounts.sudo-nopasswd — the blocker is not the lockout risk alone;
//     accounts.emptypassword carries a comparable one and is registered
//     below, disclosed through a Warning instead of declined. What actually
//     stops this one is that the finding has nowhere to point an edit.
//     passwordlessSudoers asks `sudo -n -l -U <user>` for the *effective*
//     grant rather than reading /etc/sudoers, deliberately: the rule
//     granting NOPASSWD could be a line naming the account, a line naming a
//     group it belongs to (%sudo, %wheel), or reach it through an alias or
//     an nsswitch-resolved group, across /etc/sudoers and every file
//     #includedir pulls in. Resolving that the way sysctl/origin.go resolves
//     which sysctl.d file wins is a real project and out of scope here — so
//     the finding names the account, never a file or a line, and there is
//     structurally nothing for an Edit action to target. Cloud and VM images
//     shipping this rule because the account they create has no password is
//     why the finding is common, not why it is declined; the how-to-fix
//     tells the operator to set that password and confirm it in a second
//     session before removing the rule themselves.
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
// Goose reaches agent.exec-unrestricted through GOOSE_MODE and stays Manual
// for the same reason and one more. A GOOSE_MODE in the environment wins over
// ~/.config/goose/config.yaml, and nothing on disk says whether one is set
// where Goose is started. And the host the rule is really about is the one
// that never wrote the key — auto is the default — so the remedy is an
// insert, which a replace-only editor deliberately does not do, into YAML,
// which it does not read. The fix registered for OpenClaw's spelling of the
// finding never reaches it: the checker declares Manual, and the more
// cautious of the two kinds wins.
//
// # The kernel-hardening fixes, and why they stopped being declined
//
// Sysctl findings used to be on the list above because persisting a value
// means writing an /etc/sysctl.d drop-in that usually does not exist, while
// edit actions could only modify a file already on disk.
//
// Action.CreateIfMissing removes that blocker. An unambiguous setting can now
// be Auto as one persistent, reversible edit that deliberately leaves the
// running kernel untouched. Topology-dependent settings remain Review and
// retain two independent alternatives:
//
//   - write the drop-in — persistent, effective at the next boot;
//   - `sysctl -w` — effective now, gone at the next boot.
//
// Neither dominates for those controls. An operator hardening a box they are
// about to reboot wants the first; one who cannot restart a production host
// today wants the second now and the first later. That is a choice, not a
// sequence.
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
// # The service-hardening domain, all fourteen registered
//
// The edit is trivial for every rule in this domain: a drop-in at
// /etc/systemd/system/<unit>.d/50-hostveil.conf holding a [Service] section
// and one directive, created by CreateIfMissing, reversed by deleting the
// file. What is not trivial is knowing it is safe, and for eight of the
// fourteen rules it is not knowable from a static read of the unit.
//
// Three carry the domain's original blind spot: systemd.protect-system
// breaks a service that writes under /usr; systemd.private-tmp breaks two
// services that hand each other files through /tmp; systemd.protect-home
// breaks anything whose data lives in a home directory, which on a
// self-hosted box is common. Five more collide, specifically and often, with
// the workloads this project's own audience runs: systemd.private-devices
// hides the GPU passthrough hardware transcoding needs and the TUN/TAP
// devices WireGuard, OpenVPN, and Tailscale need; systemd.protect-kernel-
// tunables blocks VPN and network daemons that legitimately touch /proc/sys;
// systemd.protect-control-groups and systemd.restrict-namespaces are
// exactly what a container runtime needs to do; systemd.memory-deny-write-
// execute is documented to break JIT runtimes — Node.js, Java, Mono,
// LuaJIT — common in self-hosted app stacks. None of that is visible from
// the unit — it depends on what the program does — so no amount of reading
// gets hostveil to "unambiguous". Those eight used to stay declined. They
// are registered now as IndividualOnly Review fixes whose Warnings name
// exactly the workloads above (riskySystemdDirectives in systemd.go): the
// person who knows whether this unit is a VPN or a JIT runtime reads that,
// and presses the button or does not. No batch turns them on.
//
// The other six carry no such blind spot, and NoNewPrivileges was the first:
// it closes the setuid path, and nothing about the unit hides whether a
// service deliberately escalates the way a unit hides which directories a
// program writes to. It is also the same protection the container domain
// fixes automatically under the same name. ProtectClock, LockPersonality,
// RestrictSUIDSGID, ProtectKernelLogs, and ProtectKernelModules followed for
// the same reason each other: the exception class is narrow and identifiable
// (a time-sync daemon, an emulation layer, an installer, a diagnostics tool,
// a service that loads modules at runtime rather than at boot), the way
// ssh.passwordauth's Warning asks "do I have SSH keys set up" rather than
// naming an invisible property of the host.
//
// This paragraph used to argue the whole domain away, on two legs that no
// longer hold for these six. One was about shape: "a drop-in and a restart
// are not two alternatives, they are one procedure in two steps, and systemd
// has no equivalent of `sysctl -w`". Action.TakesEffectOn is precisely the
// shape that objection describes — write the artifact now, name what has to
// happen for it to be in force — and every compose fix stands on it; the
// sentence predates it. The other was that the failure surfaces late: a
// service that does not come back is discovered at the next restart, which
// on a host like this can be the next reboot. That rules out Auto, but it
// does not rule out fixing it at all — it is exactly what Review is for. The
// checker declares Review for each of the six, the registration here is one
// action — Auto's shape and nothing more — and resolvedKind shows the
// operator the more cautious of the two. firewall.inactive reaches the
// screen the same way.
//
// The re-check after applying any of the six will still report the finding,
// and that is correct rather than a failure. This checker asks systemd for
// each unit's effective configuration, and systemd has not re-read the file;
// VerifyStillPresent says so in the sentence it was written for — "the
// change may not take effect until '<unit>' restarts". For the same reason
// these fixes are absent from internal/fix/roundtrip_test.go: the loop needs
// a checker that reads what the fix wrote, and this one deliberately does
// not.
//
// # The Docker daemon domain, all seven registered
//
// dockerd.* was declined whole for one structural reason and two missing
// tools. The structural reason: the checker reads the *running* daemon
// through `docker info`, and a fix edits a file the daemon reads only at
// start, so a written-but-not-restarted fix improved nothing an attacker
// could see. The tools: no editor could add a key to daemon.json without
// re-encoding it, and nothing could drop one `-H tcp://` from a unit's
// command line.
//
// Action.AfterWrite answers the first: the restart is part of the action, and
// a daemon that refuses the new file is given the old one back and started
// again, so a fix that reports success is one in force. setJSONKey
// (daemonjson.go) answers the second for daemon.json — locate the value's
// bytes, replace or insert, and refuse anything that does not parse back to
// the original with exactly one key changed — and a drop-in that overrides
// ExecStart answers it for the unit. Each fix's Warning carries what used to
// be its reason here: the API pair can sever a remote operator's channel;
// group-members cannot tell Portainer's agent from a forgotten grant;
// userns-remap hides every existing container and image. All seven are
// IndividualOnly, because restarting Docker is an outage the operator
// schedules. The two daemon defaults that need a full restart also offer to
// write the file and leave the restart to the operator, with TakesEffectOn.
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
	registerAccounts(r)
	registerCompose(r)
	registerComposeRisky(r)
	registerHostRisky(r)
	registerDockerd(r)
	registerNetworkRisky(r)
	registerFilePerms(r)
	registerSSH(r)
	registerUpdates(r)
	registerPorts(r)
	registerFirewall(r)
	registerAgent(r)
	registerSysctl(r)
	registerSystemd(r)
	registerProxy(r)
	return r
}
