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
//   - cve.* — Trivy's fixed_version is the OS package version inside the
//     image (`3.0.11-1~deb12u2`), not an image tag. There is no mapping
//     from one to the other; treating them as interchangeable is what
//     issue #473 was. The real remediation is repinning to an image whose
//     base layer ships the patched package, which needs data the per-image
//     report does not contain.
func Default() *Registry {
	r := NewRegistry()
	registerCompose(r)
	registerSSH(r)
	registerUpdates(r)
	return r
}
