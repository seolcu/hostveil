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
// The agent findings used to share one sentence, because the register argued
// all seven jointly: none of them could be edited without an editor that
// keeps JSON5 comments. internal/json5 is that editor, four of the seven are
// registered now, and the three left each say something different — which is
// what the shared sentence had been hiding.
var declineReasons = map[string]string{
	// compose
	"compose.dr005": "Moving the value into an env_file is a two-file change one action cannot make, and a secret already in backups and git history needs rotating instead.",
	"compose.ds012": "The right healthcheck depends on what the service exposes, and a guessed probe marks a working container unhealthy and stalls whatever waits on it.",

	// firewall

	// updates

	// cve
	"cve.unpatched-image": "Re-pulling the tag is the only action Hostveil has here, and no rebuild of the image carries a patch upstream has not published.",

	// ports
	"ports.exposed":           "The remediation is enabling a firewall, which can lock you out of a host reached over SSH; fixing the firewall clears this finding as a side effect.",
	"ports.exposed-admin":     "Binding a natively-installed daemon to loopback takes a config path and syntax that vary by distro, and guessing one means editing a file that is not live.",
	"ports.exposed-datastore": "Binding a native datastore to loopback takes a config file, syntax, and path that differ per daemon and per distro, none of which the finding carries.",

	// accounts
	"kube.anonymous-auth":                  "It changes how the control plane starts, in whichever configuration layer set it, and takes effect only when the node every workload runs on restarts.",
	"kube.secrets-unencrypted":             "Turning encryption on needs a restart of the control plane and a rewrite of every existing Secret, neither of which is a file edit.",
	"proxmox.webui-open":                   "Which network is the management network is not written anywhere Hostveil can read, and a wrong guess locks you out of the hypervisor's interface; LISTEN_IP also breaks clusters across subnets.",
	"proxmox.root-no-tfa":                  "A second factor is a device a person holds, and Hostveil must never enrol a credential on anyone's behalf.",
	"proxmox.enterprise-repo-unsubscribed": "The remedy is two changes in sequence, and disabling the enterprise source alone leaves the host with no Proxmox updates at all; the other remedy is a subscription key.",
	"accounts.sudo-nopasswd":               "The grant comes from sudo -l, not from reading /etc/sudoers, so nothing says which file, line, or group rule to edit — there is nowhere for an edit to point.",
	"accounts.duplicate-uid":               "Changing a UID requires migrating every file it owns across filesystems, which cannot be represented or rolled back as one action.",

	// fileperms
	"fileperms.owner": "A checkpoint records a file's contents and mode but not its previous owner, so chown would be the one change rollback could not put back.",

	// agent

	// dockerd

	// systemd
}
