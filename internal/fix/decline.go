package fix

import "strings"

// WhyNoFix returns one sentence saying what stops hostveil fixing a finding,
// or "" for a finding that has a fix.
//
// The argument for each of these lives in the doc comment on Default(), which
// is where a maintainer edits it and where TestEveryFindingIsEitherFixableOr
// DeclinedOnPurpose reads it. That comment is several pages long and no user
// will ever see it; this is the same decision, one sentence at a time, on its
// way to the finding it is about.
//
// The two are pinned against each other: internal/docs asserts that every
// finding named in the register has an entry here and that every entry here
// names a finding the register declines. Neither may grow without the other.
//
// A glob entry (sysctl.*, systemd.*) covers a whole domain, and the register
// uses one exactly where the reason is genuinely shared. Exact IDs win over
// globs, so a domain can state its shared reason and still say something
// specific about one member.
func WhyNoFix(id string) string {
	if r, ok := declineReasons[id]; ok {
		return r
	}
	if src, _, ok := strings.Cut(id, "."); ok {
		if r, ok := declineReasons[src+".*"]; ok {
			return r
		}
	}
	return ""
}

// DeclinedIDs lists every pattern with a decline reason. Tests enumerate this
// rather than a copy.
func DeclinedIDs() []string {
	out := make([]string, 0, len(declineReasons))
	for id := range declineReasons {
		out = append(out, id)
	}
	return out
}

// declineReasons is the register in Default()'s doc comment, one sentence at
// a time. Each answers the question a user actually has looking at a finding
// with no button on it: not "what is wrong" — the finding already said that —
// but "why is hostveil not doing anything about it".
//
// Every sentence is drawn from an argument already made in that comment. None
// of them is a summary of the finding, because a summary would be the one
// thing the reader already has.
//
// Five of the agent findings share a sentence, and that is not a copy-paste
// slip: the register argues all seven jointly, breaking out only
// gateway-exposed's separate recoverability failure. Writing five different
// sentences would be inventing five different reasons.
var declineReasons = map[string]string{
	// compose
	"compose.dr001": "Removing host networking leaves the service unreachable unless the ports it needs are published in its place, and the finding does not carry them.",
	"compose.dr004": "The remediation is about the env_file's permissions and whether it reached git and backups, so there is nothing in the compose file to edit.",
	"compose.dr005": "Moving the value into an env_file is a two-file change one action cannot make, and a secret already in backups and git history needs rotating instead.",
	"compose.ds001": "Deleting privileged: true removes something the author added deliberately, and hostveil cannot tell a needless one from a load-bearing one.",
	"compose.ds005": "Dropping a capability from cap_add removes something the author added deliberately, and hostveil cannot tell a needless one from a load-bearing one.",
	"compose.ds009": "Nothing in the finding says which UID the image supports, and forcing the wrong one stops an image that drops privileges in its own entrypoint.",
	"compose.ds012": "The right healthcheck depends on what the service exposes, and a guessed probe marks a working container unhealthy and stalls whatever waits on it.",
	"compose.ds016": "The only honest remediation deletes the mount, which breaks Portainer, Traefik, and Watchtower, and :ro changes nothing because the socket is an HTTP API.",
	"compose.ds017": "Adding :ro breaks a service that legitimately writes to the mount, and a static audit cannot tell a written mount from a read one.",
	"compose.ds020": "A monitoring agent legitimately needs the host PID namespace, and deleting pid: host breaks that case silently — the service starts and sees nothing.",
	"compose.ds021": "Processes that share memory legitimately need ipc: host, and deleting the line breaks that case silently — the service starts and stops working.",
	"compose.ds022": "read_only: true breaks any image that writes inside its own filesystem, and a static audit cannot learn which paths need tmpfs mounts instead.",

	// firewall
	"firewall.default-allow": "Default-deny takes effect the moment it is set, on the SSH session you are issuing it from, and an exec fix leaves no checkpoint to undo a lockout.",
	"firewall.docker-bypass": "The compose file or docker run behind the container is not in the finding, and the other remediation rewrites ufw policy that can lock you out.",

	// updates
	"updates.pending-security": "An upgrade is unbounded — a new kernel, restarted services, prompts about modified config files — and no checkpoint reverses any of it.",
	"updates.reboot-required":  "The remediation is a reboot: no checkpoint, every service on the box down, and only you know when that downtime is acceptable.",

	// cve
	"cve.unpatched-image": "Re-pulling the tag is the only action hostveil has here, and no rebuild of the image carries a patch upstream has not published.",

	// ports
	"ports.exposed":           "The remediation is enabling a firewall, which can lock you out of a host reached over SSH; fixing the firewall clears this finding as a side effect.",
	"ports.exposed-admin":     "Binding a natively-installed daemon to loopback takes a config path and syntax that vary by distro, and guessing one means editing a file that is not live.",
	"ports.exposed-datastore": "Binding a native datastore to loopback takes a config file, syntax, and path that differ per daemon and per distro, none of which the finding carries.",

	// accounts
	"accounts.emptypassword": "Locking the account has no checkpoint and it may be the only one you can reach the machine with; /etc/shadow does not say which kind it is.",
	"accounts.uid0":          "userdel orphans every file the account owns with no checkpoint to undo it, and hostveil cannot tell a backdoor from a deliberate second root.",

	// fileperms
	"fileperms.owner": "A checkpoint records a file's contents and mode but not its previous owner, so chown would be the one change rollback could not put back.",

	// agent
	"agent.auth-disabled":        "The value can come from the config, an env file, a unit, or a docker flag, so an edit may change nothing, and OpenClaw's JSON5 cannot keep its comments.",
	"agent.control-ui-insecure":  "OpenClaw's config is JSON5, hostveil has no round-tripper, and re-encoding deletes every comment in it \u2014 with no second alternative to pair the edit with.",
	"agent.elevated-enabled":     "OpenClaw's config is JSON5, hostveil has no round-tripper, and re-encoding deletes every comment in it \u2014 with no second alternative to pair the edit with.",
	"agent.exec-unrestricted":    "OpenClaw's config is JSON5, hostveil has no round-tripper, and re-encoding deletes every comment in it \u2014 with no second alternative to pair the edit with.",
	"agent.gateway-exposed":      "Rebinding can cut you off from an agent you administer remotely, and the bind may come from an env file, a unit, or a docker flag rather than the config.",
	"agent.sandbox-off":          "OpenClaw's config is JSON5, hostveil has no round-tripper, and re-encoding deletes every comment in it \u2014 with no second alternative to pair the edit with.",
	"agent.ssrf-private-network": "OpenClaw's config is JSON5, hostveil has no round-tripper, and re-encoding deletes every comment in it \u2014 with no second alternative to pair the edit with.",

	// dockerd
	"dockerd.api-tls-unverified":    "Requiring client certificates cuts off every client that has none, perhaps the one you administer through, and the daemon only reads the file at a restart.",
	"dockerd.api-unauthenticated":   "Removing the TCP endpoint severs the exact channel a remote operator may administer this host through: DOCKER_HOST, a Portainer agent, a CI runner.",
	"dockerd.group-members":         "Removing a member has no checkpoint, and the account it removes may be your own and the access you administer the daemon with.",
	"dockerd.live-restore":          "Reloading the daemon has no checkpoint, and pairing it with the daemon.json edit is write-then-apply: sequential steps, not two independent alternatives.",
	"dockerd.no-new-privileges":     "This is a daemon default that applies only to containers started after a restart, and restarting docker stops every container on the host.",
	"dockerd.socket-world-writable": "systemd recreates the socket from docker.socket at every start, so a chmod is undone at the next restart and the honest remediation is a unit drop-in.",
	"dockerd.userns-remap":          "It applies only to containers started after a restart that stops every container, and remapping rewrites the ownership of every bind mount on the host.",

	// systemd
	"systemd.no-new-privileges": "A drop-in plus a restart is one procedure in two steps rather than two alternatives, and a service that does not come back fails at the next restart.",
	"systemd.private-tmp":       "PrivateTmp=yes breaks two services that hand each other files through /tmp, which the unit does not show, and the failure surfaces at the next restart.",
	"systemd.protect-home":      "ProtectHome=yes breaks anything whose data lives in a home directory, which the unit does not show, and the failure surfaces only at the next restart.",
	"systemd.protect-system":    "ProtectSystem=full breaks a service that writes under /usr, which the unit does not show, and the failure surfaces only at the next restart.",
}
