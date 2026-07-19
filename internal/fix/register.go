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
//  1. Reversible. The action is a file edit, so applying it writes a backup
//     checkpoint that restores the original bytes exactly. Exec actions are
//     never Auto: applyExec has nothing file-backed to check point, so
//     there is no undo.
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
// # Findings deliberately left without a fix
//
// These are fixable in principle and are demoted to Manual on purpose.
// TestKnownUnregisteredFindings pins each one, so registering a fix means
// deleting an assertion and arguing with the reason.
//
//   - firewall.inactive — the only remediation is enabling a firewall, and
//     the checker records no SSH port, interface, or session data. Enabling
//     a default-deny policy on a box reached over SSH can lock the user out
//     irrecoverably, and it also drops every service the ports checker just
//     enumerated. Exec fixes have no checkpoint, so there is no undo.
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
//   - cve.<vulnerability-id> — the per-CVE findings. Trivy's fixed_version
//     is the OS package version inside the image (`3.0.11-1~deb12u2`), not
//     an image tag. There is no mapping from one to the other; treating
//     them as interchangeable is what issue #473 was. Nothing hostveil can
//     compute turns "openssl must reach 3.0.11-1~deb12u2" into an image
//     reference, so a per-CVE fix would have to invent one. These stay
//     Manual, and cve.outdated-image is registered by its exact ID
//     precisely so that no cve.* glob can ever sweep them up.
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
//   - compose.dr005 — moving a value into an env_file is a two-file change
//     where Action carries one Path, and a move that does not delete the
//     original improves nothing. More to the point, by the time the secret
//     is found it has already leaked into backups and git history, so the
//     real remediation is rotating it, which hostveil cannot do.
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
func Default() *Registry {
	r := NewRegistry()
	registerCompose(r)
	registerSSH(r)
	registerUpdates(r)
	return r
}
