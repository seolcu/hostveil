package fix

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerFilePerms wires the file-permission fixes into the registry.
//
// Exact IDs, not a "fileperms.*" glob: TestEveryRegisteredFixIsValid rejects
// globs so that introducing one is a deliberate act rather than a silent
// widening of what the registry claims to fix.
func registerFilePerms(r *Registry) {
	r.Register("fileperms.owner", buildRestoreRootOwner)
	for _, id := range []string{
		"fileperms.shadow",
		"fileperms.passwd",
		"fileperms.group",
		"fileperms.sshd-config",
		"fileperms.hostkey",
		"fileperms.gshadow",
		"fileperms.sudoers",
		"fileperms.sudoers-dropins",
		"fileperms.cron",
		"fileperms.systemd-units",
		"fileperms.docker-config",
		"fileperms.grub-config",
		"fileperms.grub2-config",
		"fileperms.at-allow",
		"fileperms.at-deny",
		"fileperms.cron-allow",
		"fileperms.cron-deny",
		"fileperms.crontab",
		"fileperms.passwd-backup",
		"fileperms.compiler",
	} {
		r.Register(id, buildTightenMode)
	}
}

// filePermsBenefit names what tightening each path actually buys, since
// buildTightenMode is one generic builder shared by every ID above (and by
// two agent-domain findings in agent.go) — there is no per-finding closure
// to hang a Benefit string on directly, so this is keyed by finding ID
// instead.
var filePermsBenefit = map[string]string{
	"agent.config-perms": "Stops other local accounts on this host reading the agent runtime's own " +
		"configuration, which can carry API keys and tool permissions.",
	"agent.secret-exposed": "Stops other local accounts reading a secret file the agent runtime keeps " +
		"in its state directory.",
	"fileperms.shadow": "Stops any account other than root (and the shadow group) reading password " +
		"hashes off disk, closing the offline-cracking path entirely.",
	"fileperms.passwd": "Stops a non-root account editing the account database directly, closing a " +
		"path to adding an account or handing itself UID 0.",
	"fileperms.group": "Stops a non-root account adding itself to a privileged group — sudo, docker " +
		"— by editing the group database directly.",
	"fileperms.sshd-config": "Stops a non-root account weakening the SSH server's own config " +
		"(re-enabling root login or password auth) to open a way back in.",
	"fileperms.hostkey": "Stops a non-root account reading this server's SSH private host key — the " +
		"one thing that would let them impersonate this host to anyone connecting.",
	"fileperms.gshadow": "Stops a non-root account reading group passwords and membership data that " +
		"/etc/gshadow is supposed to keep to root and the shadow group alone.",
	"fileperms.sudoers": "Stops a non-root account granting itself root by editing sudo's own policy file.",
	"fileperms.sudoers-dropins": "Same protection as the main sudoers file, for a drop-in carrying " +
		"the exact same authority.",
	"fileperms.cron": "Stops a non-root account scheduling a command to run as root through a " +
		"system cron definition.",
	"fileperms.systemd-units": "Stops a non-root account replacing the command a systemd unit runs " +
		"the next time it starts as root.",
	"fileperms.docker-config": "Stops other accounts on the host reading root's Docker registry " +
		"credentials, which could otherwise pull private images or publish under this host's identity.",
	"fileperms.grub-config": "Stops a non-root account reading or rewriting the bootloader " +
		"configuration, which controls what runs before any of the host's normal access controls are active.",
	"fileperms.grub2-config": "Same protection as the GRUB config, for the GRUB2 variant.",
	"fileperms.at-allow":     "Keeps control of who is allowed to schedule future one-off commands to root alone.",
	"fileperms.at-deny":      "Keeps control of who is blocked from scheduling future one-off commands to root alone.",
	"fileperms.cron-allow":   "Keeps control of who is allowed to schedule recurring cron jobs to root alone.",
	"fileperms.cron-deny":    "Keeps control of who is blocked from scheduling recurring cron jobs to root alone.",
	"fileperms.crontab": "Closes an avoidable persistence path: the system crontab can run commands " +
		"as root, and this keeps it restricted to what the scheduler itself needs.",
	"fileperms.passwd-backup": "Stops a non-root account planting a change in the passwd backup that " +
		"becomes a live credential the next time it is restored.",
	"fileperms.compiler": "Removes the system compiler from every local account's reach by default, " +
		"taking away a convenient way to build exploit code from a local foothold.",
}

// tighten returns the mode with every permission bit outside mask cleared,
// and nothing else changed.
//
// It is subtractive on purpose. Assigning the rule's MaxMode outright would
// *grant* access the file did not have: /etc/shadow at 0604 violates a 0640
// rule, and setting it to 0640 would hand the shadow group a read bit it
// never had. Masking gives 0600 instead. Only ever removing bits is what
// makes this fix unambiguous enough to apply unattended.
//
// Everything outside the permission triplet is carried through untouched:
// setuid/setgid/sticky, which rebuilding from Perm() alone would silently
// clear, and the type bits — ModeDir above all. Clearing ModeDir would not
// corrupt anything (os.Chmod ignores it), but planModes compares the result
// against the full fs.FileMode, so a directory would compare unequal to
// itself forever: preview would print a phantom 0700 → 0700 row and apply
// would checkpoint and chmod a directory that was already compliant. The
// checker judged the path on its permission bits, so those are the only bits
// this fix is entitled to touch.
func tighten(current fs.FileMode, mask fs.FileMode) fs.FileMode {
	return current&^fs.ModePerm | (current.Perm() & mask)
}

func buildTightenMode(f model.Finding) (Fix, error) {
	raw := f.Evidence["paths"]
	if raw == "" {
		return Fix{}, fmt.Errorf("finding %s has no paths to tighten", f.ID)
	}
	// Split on PathListSeparator, not EvidenceSeparator: the checker writes
	// this entry for exactly this reader, and ", " occurs inside real paths.
	// No TrimSpace either — leading and trailing whitespace are part of a
	// filename, and trimming would target a different file or none at all.
	var paths []string
	for _, p := range strings.Split(raw, model.PathListSeparator) {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return Fix{}, fmt.Errorf("finding %s has no paths to tighten", f.ID)
	}

	expected := f.Evidence["expected"]
	if expected == "" {
		return Fix{}, fmt.Errorf("finding %s has no expected mode", f.ID)
	}
	// The checker formats it with %#o, so "0640" — parse as octal explicitly
	// rather than relying on the leading zero being honoured.
	n, err := strconv.ParseUint(strings.TrimPrefix(expected, "0o"), 8, 32)
	if err != nil {
		return Fix{}, fmt.Errorf("finding %s has an unparseable expected mode %q: %w", f.ID, expected, err)
	}
	mask := fs.FileMode(n).Perm()

	label := fmt.Sprintf("Tighten permissions to %#o", mask)
	if len(paths) == 1 {
		label = fmt.Sprintf("Tighten %s to %#o", paths[0], mask)
	}

	return Fix{
		Label: label,
		Kind:  model.RemediationAuto,
		Actions: []Action{{
			Label:    label,
			Benefit:  filePermsBenefit[f.ID],
			Kind:     ActionMode,
			Paths:    paths,
			SafeRoot: f.Evidence["root"],
			Mode:     func(cur fs.FileMode) fs.FileMode { return tighten(cur, mask) },
		}},
	}, nil
}

// buildRestoreRootOwner gives the files back to root, user only.
//
// It was declined for two reasons. A checkpoint had nowhere to put an
// owner, so this would have been the one fix a rollback could not undo; it
// records the prior uid and gid now (history.Owner). And the right group
// differs by distribution; the group is left exactly as it is, because the
// owner is the half of this finding that is wrong. What stays true is the
// Warning: ownership landing on the wrong account is usually a symptom, and
// chowning the files hostveil knows about fixes the visible part.
func buildRestoreRootOwner(f model.Finding) (Fix, error) {
	var paths []string
	for _, p := range strings.Split(f.Evidence["owner-paths"], model.PathListSeparator) {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return Fix{}, fmt.Errorf("finding %s names no files", f.ID)
	}
	root := 0
	return Fix{
		Label: "Give " + strings.Join(paths, ", ") + " back to root", Kind: model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{{
			Label: "Set the owning user of each file to root, keeping its group",
			Benefit: "The account that owned these files loses the access ownership gave it — every password hash, " +
				"in /etc/shadow's case — and the permission bits mean what they appear to again.",
			Warning: "If a service runs as that account and reads one of these files on purpose, it stops being " +
				"able to. And if several files changed owner at once, something put them there — a restore run as " +
				"the wrong user, an archive extracted with its own uids — and other files are likely affected too. " +
				"The previous owner is checkpointed and a rollback restores it.",
			Kind: ActionMode, Paths: paths,
			Mode:     func(cur fs.FileMode) fs.FileMode { return cur },
			ChownUID: &root,
		}},
	}, nil
}
