package systemd

import (
	"fmt"
	"path"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// rule audits one property of one unit.
//
// Every finding is Manual. A drop-in under /etc/systemd/system/<unit>.d is a
// two-line file and hostveil could certainly write it, but writing it is not
// the same as knowing it is safe: ProtectSystem=full breaks a service that
// writes under /usr, PrivateTmp=yes breaks two services that pass each other
// files through /tmp, and neither failure appears until the next restart —
// which on a self-hosted box is the next reboot, at which point the service
// that did not come back is the one holding the operator's data.
//
// That is the "unambiguous" test in fix.Default's standard, and these do not
// meet it. Nor is Review available: a Review fix needs two genuinely
// independent alternatives, and there is only one thing to do here. So the
// remediation is a precise instruction — the exact path and the exact two
// lines — and the operator decides. See TestKnownUnregisteredFindings.
type rule struct {
	id    string
	title string
	// sev is the severity for a service running as root; sevNonRoot is the
	// severity when it runs as somebody else, and is zero when the rule does
	// not care.
	sev        model.Severity
	sevNonRoot model.Severity
	desc       string
	// directive is the [Service] line that turns the protection on.
	directive string
	flagged   func(u unit) bool
	// remediation is how much human judgement this rule needs, and it is
	// per-rule rather than per-domain because the four differ.
	//
	// Three of them break something the unit does not show — a service that
	// hands another files through /tmp, one whose data lives in a home
	// directory, one that writes under /usr — so hostveil has no way to tell
	// a safe unit from an unsafe one and stays out of it. NoNewPrivileges
	// carries no such blind spot: it closes the setuid path and nothing
	// about the unit hides whether that matters.
	//
	// Review rather than Auto because a service that deliberately escalates
	// stops coming back, and that is not a thing to do while nobody is
	// watching. The registry's fix is one action, which is Auto's shape;
	// resolvedKind takes the more cautious of the two, so this is what the
	// operator is shown.
	remediation model.RemediationKind
}

// on reports whether systemd read a boolean property as enabled. It prints
// booleans as "yes"/"no", and an empty value is a property this systemd does
// not know — which is not evidence that the protection is off.
func on(v string) bool { return v == "yes" }

// known reports whether systemd answered about a property at all. An older
// systemd that does not implement one prints nothing for it, and reporting
// "the protection is off" on the strength of a silence would be inventing a
// finding out of a blind spot.
func known(v string) bool { return v != "" }

// off reports whether an enumerated protection is disabled.
//
// ProtectSystem and ProtectHome are not booleans — systemd prints
// no/yes/full/strict for the first and no/yes/read-only/tmpfs for the second —
// so the test is against the one value that means "not protected" rather than
// against `!on(v)`, which would flag "full" and "read-only" as failures.
//
// Only "no", and deliberately not also "off": systemd normalizes every
// spelling of disabled to "no" in `show` output, and a second arm for a value
// it never emits is a branch no test can reach. This domain's first draft had
// one, checked against a real host's 77 units, and found no/yes/full/strict
// and nothing else.
func off(v string) bool { return v == "no" }

var rules = []rule{
	{
		id:    "systemd.no-new-privileges",
		title: "A service can gain privileges while running",
		// A root service can already do anything, so the setuid path this
		// closes buys little there; for a service running as somebody else it
		// is the difference between a compromise staying inside that account
		// and walking out of it.
		sev:        model.SeverityLow,
		sevNonRoot: model.SeverityMedium,
		desc: "NoNewPrivileges is off, so anything this service runs can gain privileges through a setuid binary — the standard way a foothold inside a service becomes a foothold outside it. " +
			"It costs nothing on a service that does not deliberately escalate, which is why it is the same protection the container domain checks for under the name no-new-privileges.",
		directive:   "NoNewPrivileges=yes",
		remediation: model.RemediationReview,
		flagged:     func(u unit) bool { return known(u.NoNewPrivileges) && !on(u.NoNewPrivileges) },
	},
	{
		id:    "systemd.protect-system",
		title: "A service can write anywhere on the system",
		// The reverse of the rule above: this is what stands between a root
		// service and the rest of the filesystem, and it is worth most
		// exactly where NoNewPrivileges is worth least.
		sev:        model.SeverityMedium,
		sevNonRoot: model.SeverityLow,
		desc: "ProtectSystem is off, so this service can write to /usr, /boot, and /etc. A compromised service that can edit /etc owns every login on the host; one that can write /usr can replace a binary something else runs as root. " +
			"ProtectSystem=full mounts those read-only for this service alone and needs no change to the program itself.",
		directive: "ProtectSystem=full",
		flagged:   func(u unit) bool { return known(u.ProtectSystem) && off(u.ProtectSystem) },
	},
	{
		id:         "systemd.protect-home",
		title:      "A service can read every user's home directory",
		sev:        model.SeverityMedium,
		sevNonRoot: model.SeverityLow,
		desc: "ProtectHome is off, so this service can read /home, /root, and /run/user — the SSH private keys, cloud credentials, and password databases of everyone with an account on this host. " +
			"Almost no self-hosted service has any business there; ProtectHome=yes hides them from this service without affecting anything else.",
		directive: "ProtectHome=yes",
		flagged:   func(u unit) bool { return known(u.ProtectHome) && off(u.ProtectHome) },
	},
	{
		id:    "systemd.private-tmp",
		title: "A service shares /tmp with everything else on the host",
		sev:   model.SeverityLow,
		desc: "PrivateTmp is off, so this service reads and writes the same /tmp as every other process. That is the ground the symlink and hardlink races live on: another local process can predict a temporary file's name and have this service overwrite something it chooses. " +
			"PrivateTmp=yes gives the service a /tmp of its own.",
		directive: "PrivateTmp=yes",
		flagged:   func(u unit) bool { return known(u.PrivateTmp) && !on(u.PrivateTmp) },
	},
	{id: "systemd.private-devices", title: "A service can access host devices", sev: model.SeverityMedium, desc: "PrivateDevices is off, so a compromised service can reach physical and virtual device nodes exposed under /dev.", directive: "PrivateDevices=yes", flagged: func(u unit) bool { return known(u.PrivateDevices) && !on(u.PrivateDevices) }},
	{id: "systemd.protect-kernel-tunables", title: "A service can change kernel tunables", sev: model.SeverityMedium, desc: "ProtectKernelTunables is off, leaving /proc/sys and related kernel controls writable to a sufficiently privileged service.", directive: "ProtectKernelTunables=yes", flagged: func(u unit) bool { return known(u.ProtectKernelTunables) && !on(u.ProtectKernelTunables) }},
	{id: "systemd.protect-kernel-modules", title: "A service can load or alter kernel modules", sev: model.SeverityMedium, desc: "ProtectKernelModules is off, so a compromised privileged service can modify the code running in the kernel.", directive: "ProtectKernelModules=yes", flagged: func(u unit) bool { return known(u.ProtectKernelModules) && !on(u.ProtectKernelModules) }},
	{id: "systemd.protect-control-groups", title: "A service can alter control groups", sev: model.SeverityMedium, desc: "ProtectControlGroups is off, allowing a privileged service to manipulate cgroups used to isolate and account for other workloads.", directive: "ProtectControlGroups=yes", flagged: func(u unit) bool { return known(u.ProtectControlGroups) && !on(u.ProtectControlGroups) }},
	{id: "systemd.protect-kernel-logs", title: "A service can read or alter kernel logs", sev: model.SeverityLow, desc: "ProtectKernelLogs is off, so a compromised service may obtain sensitive kernel diagnostics or interfere with them.", directive: "ProtectKernelLogs=yes", flagged: func(u unit) bool { return known(u.ProtectKernelLogs) && !on(u.ProtectKernelLogs) }},
	{id: "systemd.protect-clock", title: "A service can change the system clock", sev: model.SeverityLow, desc: "ProtectClock is off, so a privileged service can alter system or hardware clocks and undermine logs, certificates, and scheduled work.", directive: "ProtectClock=yes", flagged: func(u unit) bool { return known(u.ProtectClock) && !on(u.ProtectClock) }},
	{id: "systemd.restrict-suid-sgid", title: "A service can create setuid or setgid files", sev: model.SeverityMedium, desc: "RestrictSUIDSGID is off, leaving a path for a compromised service to create files that grant privileges when executed later.", directive: "RestrictSUIDSGID=yes", flagged: func(u unit) bool { return known(u.RestrictSUIDSGID) && !on(u.RestrictSUIDSGID) }},
	{id: "systemd.restrict-namespaces", title: "A service can create every namespace type", sev: model.SeverityMedium, desc: "RestrictNamespaces is off, exposing namespace-related kernel attack surface that most ordinary services do not need.", directive: "RestrictNamespaces=yes", flagged: func(u unit) bool { return known(u.RestrictNamespaces) && !on(u.RestrictNamespaces) }},
	{id: "systemd.lock-personality", title: "A service can change its execution personality", sev: model.SeverityLow, desc: "LockPersonality is off, allowing a compromised process to switch execution domains and reach compatibility code it normally would not use.", directive: "LockPersonality=yes", flagged: func(u unit) bool { return known(u.LockPersonality) && !on(u.LockPersonality) }},
	{id: "systemd.memory-deny-write-execute", title: "A service can create writable executable memory", sev: model.SeverityMedium, desc: "MemoryDenyWriteExecute is off, so injected code can more easily create or modify executable memory. Some JIT runtimes legitimately require it.", directive: "MemoryDenyWriteExecute=yes", flagged: func(u unit) bool { return known(u.MemoryDenyWriteExecute) && !on(u.MemoryDenyWriteExecute) }},
}

// severityFor picks the severity a rule carries on this unit. A rule with no
// non-root severity means the same either way.
func (r rule) severityFor(u unit) model.Severity {
	if !u.root() && r.sevNonRoot != 0 {
		return r.sevNonRoot
	}
	return r.sev
}

// dropInPath is where the operator's own override for a unit belongs. Under
// /etc, so it outranks the unit file and any drop-in a package ships, and
// numbered so a later file of the operator's own still wins.
// dropInPath is where the fix writes, and the name is chosen rather than
// fixed.
//
// systemd.unit(5): "Multiple drop-in files with different names are applied in
// lexicographic order, regardless of which of the directories they reside in."
// So a vendor's /usr/lib/systemd/system/<unit>.d/90-vendor.conf beats
// /etc/systemd/system/<unit>.d/50-hostveil.conf — the /etc-over-/usr rule
// applies only to files with the *same* name. A drop-in that loses is the
// worst available outcome and the one persistSysctl exists to avoid: the file
// appears, the fix reports success, a checkpoint is recorded, and the value
// comes back at the next daemon-reload with nothing to explain it.
//
// The name is picked to sort after everything systemd says it loaded, which
// wins whatever those files contain — reading them to find out whether they
// set this particular directive would be a second parser answering a question
// systemd has already answered. 50- stays the name on the ordinary host,
// because that is what the docs and the finding's own instructions say.
//
// "" means no name wins, and the fix refuses rather than writing one that
// cannot work.
func dropInPath(unitID, loaded string) string {
	dir := "/etc/systemd/system/" + unitID + ".d/"
	last := ""
	for _, p := range strings.Fields(loaded) {
		if b := path.Base(p); b > last {
			last = b
		}
	}
	for _, name := range []string{"50-hostveil.conf", "99-hostveil.conf"} {
		if name > last {
			return dir + name
		}
	}
	return ""
}

// howToFix is the instruction, which has to name a file — and there is one
// case where no file it could name would work.
//
// A drop-in wins on filename, so when systemd has already loaded one that
// sorts after anything hostveil would write, the honest instruction is not
// "create this file": it is that the operator has to deal with the file that
// outranks it. Telling them to write one that loses would be advice that
// cannot work, which the environment reference test calls the worst kind.
func howToFix(u unit, r rule) string {
	dropIn := dropInPath(u.ID, u.DropInPaths)
	if dropIn == "" {
		return fmt.Sprintf(
			"A drop-in that systemd loads after anything hostveil could write is already in "+
				"place for this unit (%s), and drop-ins are applied in filename order whichever "+
				"directory they are in — so a new file under /etc/systemd/system/%s.d/ would be "+
				"overridden. Set `%s` in the file that sorts last, or rename it, then run "+
				"`systemctl daemon-reload` and `systemctl restart %s`.",
			u.DropInPaths, u.ID, r.directive, u.ID)
	}
	return fmt.Sprintf(
		"Create %s containing:\n\n    [Service]\n    %s\n\nThen run `systemctl daemon-reload` and `systemctl restart %s`. "+
			"Restart it while you are watching: these protections change what the service can reach, and a service that needs what one of them hides fails at start rather than misbehaving quietly. "+
			"Remove the file to undo it.",
		dropIn, r.directive, u.ID)
}

func (r rule) finding(u unit) model.Finding {
	runAs := u.User
	if runAs == "" {
		runAs = "root (no User= set)"
	}
	kind := r.remediation
	if kind == model.RemediationUnset {
		kind = model.RemediationManual
	}
	return model.NewFinding(r.id, r.title, r.severityFor(u), model.SourceSystemd,
		kind,
		model.WithService(u.ID),
		// Where the fix layer writes, decided by the half that computes it.
		// internal/fix cannot import this package, and a path recomputed
		// there would be a second answer to a question with one — the same
		// reason the compose checker carries "file".
		model.WithMetadata("dropin", dropInPath(u.ID, u.DropInPaths)),
		model.WithDescription(r.desc),
		model.WithHowToFix(howToFix(u, r)),
		model.WithEvidence("unit", u.FragmentPath),
		model.WithEvidence("runs as", runAs),
	)
}
