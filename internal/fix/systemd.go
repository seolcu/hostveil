package fix

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerSystemd registers the systemd findings whose remediation hostveil
// can write down.
//
// The domain has fourteen rules. Eight stay declined, because each breaks
// something the unit does not show: PrivateTmp breaks two services that hand
// each other files through /tmp, ProtectHome breaks anything whose data lives
// in a home directory, ProtectSystem breaks a service that writes under /usr,
// and the other five collide with workloads this project's own audience
// runs — container runtimes, GPU passthrough, VPN tunnels, JIT runtimes; see
// register.go for the reasoning behind each. The other six — NoNewPrivileges
// and the five below it — carry no such blind spot: each closes one narrow,
// well-known capability, and nothing about the unit hides whether a
// particular service needs it.
//
// The reason this domain was declined whole has expired. It read "a drop-in
// plus a restart is one procedure in two steps rather than two alternatives",
// and Action.TakesEffectOn is exactly the shape that objection describes:
// write the artifact now, name what has to happen for it to be in force.
// Every compose fix runs on it. The sentence was written before it existed.
//
// The other half of that reason still holds for all six registered here — a
// service that deliberately escalates, or that needs one of these narrow
// capabilities, stops coming back — so every one is Review, declared by the
// checker. The action in each case is one edit, which is Auto's shape;
// resolvedKind takes the more cautious of the two.
func registerSystemd(r *Registry) {
	r.Register("systemd.no-new-privileges", buildSystemdNoNewPrivileges)
	r.Register("systemd.protect-clock", buildSystemdProtectClock)
	r.Register("systemd.lock-personality", buildSystemdLockPersonality)
	r.Register("systemd.restrict-suid-sgid", buildSystemdRestrictSUIDSGID)
	r.Register("systemd.protect-kernel-logs", buildSystemdProtectKernelLogs)
	r.Register("systemd.protect-kernel-modules", buildSystemdProtectKernelModules)

	for _, d := range riskySystemdDirectives {
		r.Register(d.id, d.build)
	}
}

// riskySystemdDirectives are the eight protections that were declined because
// each breaks a kind of service the unit does not reveal. That is still true,
// and it is what the Warning on each one now says instead of the register.
// They are IndividualOnly: `fix --all --review` would otherwise turn every one
// of them on for every unit on the host at once, and the person who knows
// whether this unit is a container runtime or a JIT is the one who has to
// press it.
var riskySystemdDirectives = []riskyDirective{
	{"systemd.private-tmp", "PrivateTmp", "yes",
		"Gives the service a /tmp of its own, so another local process can no longer race it with a predictable temporary file name.",
		"Two services that hand each other files through /tmp stop seeing each other's files, and anything this service left in /tmp is not there after the restart."},
	{"systemd.protect-home", "ProtectHome", "yes",
		"Hides /home, /root and /run/user from the service, so a compromise of it cannot read anyone's SSH keys or cloud credentials.",
		"A service whose data or configuration lives in a home directory — a media server pointed at ~/Videos, a sync client — cannot reach it after the restart and fails or comes up empty."},
	{"systemd.protect-system", "ProtectSystem", "full",
		"Mounts /usr, /boot and /etc read-only for this service alone, so a compromise of it cannot replace a binary or edit a login file.",
		"A service that writes its own configuration under /etc or updates files under /usr — a package manager, a self-updating agent — fails when it tries."},
	{"systemd.private-devices", "PrivateDevices", "yes",
		"Gives the service a minimal /dev with no physical devices, so a compromise of it cannot reach disks, GPUs or other device nodes directly.",
		"A service that uses hardware — GPU transcoding, a USB or serial device, a TUN interface for a VPN — loses it after the restart."},
	{"systemd.protect-kernel-tunables", "ProtectKernelTunables", "yes",
		"Makes /proc/sys and /sys read-only for the service, so a compromise of it cannot change kernel networking or security settings.",
		"A service that manages kernel settings on purpose — a VPN enabling IP forwarding, a network manager, a container runtime — cannot after the restart."},
	{"systemd.protect-control-groups", "ProtectControlGroups", "yes",
		"Makes the cgroup tree read-only for the service, so a compromise of it cannot loosen the limits that isolate other workloads.",
		"Container runtimes and anything that creates or manages cgroups itself (Docker, containerd, Kubernetes, LXC) stop working after the restart."},
	{"systemd.restrict-namespaces", "RestrictNamespaces", "yes",
		"Stops the service creating namespaces, removing kernel attack surface that most daemons never use.",
		"Container runtimes, sandboxes, browsers and anything else that isolates its children with namespaces fail to start them after the restart."},
	{"systemd.memory-deny-write-execute", "MemoryDenyWriteExecute", "yes",
		"Stops the service creating memory that is both writable and executable, which is how injected code usually gets to run.",
		"JIT runtimes — Node.js, Java, .NET, PHP with JIT, LuaJIT, browsers — need exactly that memory and crash or refuse to start after the restart."},
}

type riskyDirective struct {
	id, key, value, benefit, warning string
}

// systemdRollbackNote is the reassurance half of each risky Warning: the
// drop-in is a file hostveil created, so undoing it is deleting it.
const systemdRollbackNote = "The drop-in is a new file with a checkpoint, so rolling it back deletes it; restart the service while you are watching."

func (d riskyDirective) build(f model.Finding) (Fix, error) {
	fx, err := systemdDropIn(f, d.key, d.value, d.benefit, d.warning+" "+systemdRollbackNote)
	// Declared Review here rather than left to the checker: the shape is
	// Auto's, one edit, but the reason these were declined is exactly the
	// one Auto excludes, and a registry that says Auto about them is a
	// registry the docs and every other reader of it would believe.
	fx.Kind = model.RemediationReview
	fx.IndividualOnly = true
	return fx, err
}

// serviceDirective matches an existing assignment of the directive's key
// anywhere in the file, in systemd's own spelling: the key, optional spaces,
// '=', the rest of the line.
func serviceDirective(key string) *regexp.Regexp {
	return regexp.MustCompile(`(?mi)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=.*$`)
}

func buildSystemdNoNewPrivileges(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "NoNewPrivileges", "yes",
		"Closes the setuid escalation path out of this unit — a compromised process cannot gain "+
			"more privilege than the service already had, the same protection compose.ds006 gives a "+
			"container.",
		"Closes the setuid path out of this service. A service that deliberately "+
			"escalates — anything calling a setuid helper — stops working, and it "+
			"stops at the next restart rather than now.")
}

// Five of the remaining thirteen protections registered below, alongside
// no-new-privileges: chosen because the failure mode is narrow enough for an
// operator reading the finding to actually assess it, the way ssh.passwordauth
// asks "do I have SSH keys set up" rather than "does something on this host
// depend on an invisible property of the unit". The other eight collide with
// workloads this project's own audience runs — container runtimes needing
// namespaces and cgroups, GPU passthrough and VPN tunnels needing /dev and
// /proc/sys, JIT runtimes needing writable executable memory, and three whose
// blind spot is unchanged from the domain's original three (/usr, /tmp, home
// directories) — and stay declined; see register.go.

func buildSystemdProtectClock(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "ProtectClock", "yes",
		"Stops the unit changing the system or hardware clock, closing off a way a compromised "+
			"service could hide its tracks by tampering with timestamps or break time-based "+
			"authentication.",
		"Only time-sync daemons (chronyd, ntpd, systemd-timesyncd) legitimately need "+
			"to change the system or hardware clock. A service that is not one of "+
			"those stops being able to, at the next restart.")
}

func buildSystemdLockPersonality(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "LockPersonality", "yes",
		"Stops the unit switching to an alternate execution personality, closing an old technique "+
			"for bypassing ASLR.",
		"Needing an alternate execution personality is rare outside emulation and "+
			"compatibility layers. An ordinary service is unaffected; one that "+
			"needs one fails at the next restart.")
}

func buildSystemdRestrictSUIDSGID(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "RestrictSUIDSGID", "yes",
		"Stops the unit creating new setuid or setgid files, closing a persistence and "+
			"privilege-escalation path a compromised service could otherwise leave behind for later.",
		"Only a service that itself creates setuid or setgid files — a package "+
			"manager, an installer — needs this off. An ordinary network daemon "+
			"does not create such files and is unaffected.")
}

func buildSystemdProtectKernelLogs(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "ProtectKernelLogs", "yes",
		"Stops the unit reading /dev/kmsg directly, closing an information-leak path that can hand "+
			"an attacker kernel addresses useful for a further exploit.",
		"Only a service that reads kernel logs directly — a diagnostics tool, an "+
			"agent reading /dev/kmsg — needs this off. Most services never touch it.")
}

func buildSystemdProtectKernelModules(f model.Finding) (Fix, error) {
	return systemdDropIn(f, "ProtectKernelModules", "yes",
		"Stops the unit loading or removing kernel modules itself, closing a direct path to "+
			"running arbitrary code in kernel space from what should be an ordinary service.",
		"Only a service that loads or removes kernel modules itself at runtime — "+
			"rather than modules already loaded at boot — needs this off.")
}

// systemdDropIn builds the edit that turns one [Service] directive on.
//
// The path is the finding's, not one computed here: internal/check/systemd
// works it out from the unit id and carries it, and a second computation here
// would be a second answer to a question that has one. It is also the path
// that checker's own how-to tells the operator to create, which is what makes
// the fix and the instructions the same instruction.
func systemdDropIn(f model.Finding, key, value, benefit, warning string) (Fix, error) {
	// Empty means the checker found a drop-in systemd loads after anything
	// hostveil could write. Drop-ins are applied in filename order whichever
	// directory they live in (systemd.unit(5)), so the file this fix would
	// create is one the next daemon-reload overrides — it would appear, report
	// success, take a checkpoint, and change nothing. That is persistSysctl's
	// rule, and refusing here is what makes it true of this domain too: the
	// finding falls back to Manual and its how-to-fix names the file that
	// outranks it.
	path := f.Metadata["dropin"]
	if path == "" {
		return Fix{}, fmt.Errorf("no drop-in filename for %s would sort after the ones systemd "+
			"has already loaded for %s, so any file written here would be overridden", f.ID, f.Service)
	}
	unit := f.Service
	if unit == "" {
		return Fix{}, fmt.Errorf("finding %s names no unit", f.ID)
	}
	line := key + "=" + value

	return Fix{
		FindingID: f.ID,
		Label:     "Write " + path,
		Kind:      model.RemediationAuto, // one action; the checker asks for Review
		Actions: []Action{{
			Label:   "Set " + line + " for " + unit,
			Benefit: benefit,
			Warning: warning,
			Kind:    ActionEdit,
			Path:    path,
			// The drop-in does not exist — if it did, the directive would be
			// set and the finding would not have fired. Undoing the fix means
			// deleting the file, which is what the checker's own instructions
			// already tell the operator.
			CreateIfMissing: true,
			// systemd reads unit files once. Until it is told to read them
			// again, `systemctl show` keeps reporting the old value, so the
			// re-check will still report this finding — correctly, and that
			// is what VerifyStillPresent is for.
			TakesEffectOn: "`systemctl daemon-reload && systemctl restart " + unit + "`",
			Transform:     setServiceDirective(key, line),
		}},
	}, nil
}

// setServiceDirective returns the transform that leaves the file with exactly
// one assignment of key, set to line.
//
// Four shapes reach it. An absent file arrives as nil and gets a whole
// drop-in. A file that already says the right thing is returned untouched —
// applying a fix twice is not an error the operator should have to avoid. A
// file that assigns the key differently has that line replaced rather than
// another appended: systemd takes the last assignment so appending would
// work, and a file carrying both is not wrong so much as evidence of a tool
// that does not know what it has done. A file with no [Service] section at
// all gets one, because a bare directive in a drop-in belongs to no section
// and systemd ignores it.
func setServiceDirective(key, line string) func([]byte) ([]byte, error) {
	re := serviceDirective(key)
	return func(in []byte) ([]byte, error) {
		if len(bytes.TrimSpace(in)) == 0 {
			return []byte("[Service]\n" + line + "\n"), nil
		}
		if m := re.Find(in); m != nil {
			if strings.EqualFold(strings.Join(strings.Fields(string(m)), ""), line) {
				return in, nil
			}
			return re.ReplaceAll(in, []byte(line)), nil
		}

		out := string(in)
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		// Append under the last [Service] section, or add one. Appending at
		// the end of the file would land inside whatever section happens to
		// be last — [Unit] or [Install] — where systemd would ignore it. The
		// SSH domain learned the same lesson about Match blocks.
		idx := regexp.MustCompile(`(?mi)^\[Service\][ \t]*$`).FindAllStringIndex(out, -1)
		if len(idx) == 0 {
			return []byte(out + "\n[Service]\n" + line + "\n"), nil
		}
		start := idx[len(idx)-1][1]
		end := len(out)
		if next := regexp.MustCompile(`(?m)^\[`).FindStringIndex(out[start:]); next != nil {
			end = start + next[0]
			// Back over the blank line that separates the sections. Inserting
			// after it leaves the directive sitting against the next header,
			// which systemd reads correctly and a person does not: it looks
			// like it belongs to [Install].
			for end > start && strings.HasSuffix(out[:end], "\n\n") {
				end--
			}
		}
		return []byte(out[:end] + line + "\n" + out[end:]), nil
	}
}
