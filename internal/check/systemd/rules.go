package systemd

import (
	"fmt"

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
		directive: "NoNewPrivileges=yes",
		flagged:   func(u unit) bool { return known(u.NoNewPrivileges) && !on(u.NoNewPrivileges) },
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
func dropInPath(unitID string) string {
	return "/etc/systemd/system/" + unitID + ".d/50-hostveil.conf"
}

func (r rule) finding(u unit) model.Finding {
	runAs := u.User
	if runAs == "" {
		runAs = "root (no User= set)"
	}
	return model.NewFinding(r.id, r.title, r.severityFor(u), model.SourceSystemd,
		model.RemediationManual,
		model.WithService(u.ID),
		model.WithDescription(r.desc),
		model.WithHowToFix(fmt.Sprintf(
			"Create %s containing:\n\n    [Service]\n    %s\n\nThen run `systemctl daemon-reload` and `systemctl restart %s`. "+
				"Restart it while you are watching: these protections change what the service can reach, and a service that needs what one of them hides fails at start rather than misbehaving quietly. "+
				"Remove the file to undo it.",
			dropInPath(u.ID), r.directive, u.ID)),
		model.WithEvidence("unit", u.FragmentPath),
		model.WithEvidence("runs as", runAs),
	)
}
