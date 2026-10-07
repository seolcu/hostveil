package fix

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
)

// The compose findings below were in the declined register until Review was
// allowed a single action. Each has exactly one mechanical remediation, and
// each can break a deployment that set the key on purpose — which is why none
// of them is Auto and every one of them says so in its Warning. What changed
// is not the risk, it is who decides: the operator reads the Warning and the
// diff, and presses the button or does not.
//
// None of them is applied by a batch, not even `fix --all --review`: each is
// IndividualOnly, because the person who has to read the Warning is the one
// who knows whether this service set the key on purpose.
//
// They are all file edits, so every one leaves a checkpoint and rolls back
// exactly. None of them is in force until the service is recreated, and
// composeEdit records that through TakesEffectOn the same way the Auto
// compose fixes do.
func registerComposeRisky(r *Registry) {
	r.Register("compose.ds001", buildRemovePrivileged)
	r.Register("compose.ds005", buildRemoveCapability)
	r.Register("compose.dr001", buildRemoveHostNetwork)
	r.Register("compose.ds020", buildRemoveHostPid)
	r.Register("compose.ds021", buildRemoveHostIpc)
	r.Register("compose.ds026", buildRemoveHostUserns)
	r.Register("compose.ds023", buildRemoveSeccompUnconfined)
	r.Register("compose.ds024", buildRemoveAppArmorUnconfined)
	r.Register("compose.ds016", buildRemoveDockerSocket)
	r.Register("compose.ds017", buildMountReadOnly)
	r.Register("compose.ds022", buildReadOnlyRootfs)
	r.Register("compose.ds009", buildRunAsNonRoot)
}

// rollbackNote is the half of every Warning here that is reassurance rather
// than risk, and it is the same sentence for all of them.
const rollbackNote = "This is a file edit with a checkpoint, so rolling it back restores the line exactly."

// composeKeyTarget is the file that sets what a removal takes out.
//
// A removal is the opposite question from composeScalarTarget's: not which
// file decides a value, but which file wrote the line. Deleting it from a file
// that does not contain it is an error, and deleting it from one of two that
// do leaves the other one in force while the finding clears — so exactly one
// file must carry it, or hostveil says it cannot tell.
func composeKeyTarget(f model.Finding, has func(compose.Service) bool) (string, error) {
	files, err := composeFiles(f)
	if err != nil {
		return "", err
	}
	if len(files) == 1 {
		return files[0], nil
	}
	var carrying []string
	for _, path := range files {
		proj, err := compose.ParseFile(path)
		if err != nil {
			continue
		}
		if svc, ok := proj.Services[f.Service]; ok && has(svc) {
			carrying = append(carrying, path)
		}
	}
	switch len(carrying) {
	case 1:
		return carrying[0], nil
	case 0:
		return "", fmt.Errorf("finding %s: none of the %d files this project is composed from sets it on %s alone, so there is no line to remove",
			f.ID, len(files), f.Service)
	default:
		return "", fmt.Errorf("finding %s: %s all set it on %s, and removing it from one would leave the others in force",
			f.ID, strings.Join(carrying, " and "), f.Service)
	}
}

// riskyComposeFix is one Review action that edits the one file carrying the
// setting.
func riskyComposeFix(f model.Finding, has func(compose.Service) bool, label, action, benefit, risk string,
	mutate func(d *compose.Doc, svc string) error) (Fix, error) {
	path, err := composeKeyTarget(f, has)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	return Fix{
		Label:          label,
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{composeEdit(path, action, benefit,
			risk+" "+rollbackNote+" "+recreateNote(svc), svc,
			func(d *compose.Doc) error { return mutate(d, svc) })},
	}, nil
}

func buildRemovePrivileged(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, func(s compose.Service) bool { return s.Privileged },
		"Remove privileged mode from "+f.Service,
		"Delete `privileged: true`",
		"A compromise of this container stops being a compromise of the host: it loses direct access to "+
			"every device and almost every kernel capability root has.",
		"If the service really does need host devices or kernel access — a VPN client, a hardware "+
			"monitor, Docker-in-Docker — it will fail to start or quietly lose that function. Check its "+
			"logs after recreating it, and if it needs one specific capability, grant just that with cap_add.",
		func(d *compose.Doc, svc string) error { return d.RemoveKey(svc, "privileged") })
}

func buildRemoveCapability(f model.Finding) (Fix, error) {
	capability := f.Evidence["capability"]
	if capability == "" {
		return Fix{}, fmt.Errorf("finding %s has no capability to remove", f.ID)
	}
	return riskyComposeFix(f, func(s compose.Service) bool {
		for _, c := range s.CapAdd {
			if strings.EqualFold(strings.TrimPrefix(strings.ToUpper(c), "CAP_"), strings.TrimPrefix(strings.ToUpper(capability), "CAP_")) {
				return true
			}
		}
		return false
	},
		"Drop "+capability+" from "+f.Service,
		"Remove "+capability+" from cap_add",
		"Takes away a capability that can be escalated into a container escape, so a compromise of "+
			"this service stays inside it.",
		"Services add capabilities on purpose: NET_ADMIN for a VPN or a firewall container, SYS_ADMIN "+
			"for FUSE mounts, SYS_PTRACE for a debugger. If this one needs "+capability+", it will fail "+
			"the operation that uses it once recreated.",
		func(d *compose.Doc, svc string) error { return d.RemoveCapAdd(svc, capability) })
}

func buildRemoveHostNetwork(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, func(s compose.Service) bool { return s.NetworkMode == "host" },
		"Take "+f.Service+" off the host network",
		"Delete `network_mode: host`",
		"The container gets its own network namespace again, so it can no longer bind any port on the "+
			"host or reach services that listen only on the host's loopback.",
		"With host networking gone, whatever port the service listens on is no longer reachable from "+
			"outside the container until you publish it under `ports:` — hostveil cannot tell which ports "+
			"those are. Services that discover devices on the LAN (Home Assistant, Plex/Jellyfin DLNA) "+
			"also lose that.",
		func(d *compose.Doc, svc string) error { return d.RemoveKey(svc, "network_mode") })
}

func buildRemoveHostPid(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, func(s compose.Service) bool { return s.Pid == "host" },
		"Stop sharing the host PID namespace with "+f.Service,
		"Delete `pid: host`",
		"The container stops seeing every process on the host, along with the credentials their "+
			"command lines and environments tend to carry, and loses the ability to signal them.",
		"A monitoring agent (node-exporter, netdata, a security scanner) uses this to observe the host; "+
			"without it, it starts fine and reports only on itself.",
		func(d *compose.Doc, svc string) error { return d.RemoveKey(svc, "pid") })
}

func buildRemoveHostIpc(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, func(s compose.Service) bool { return s.Ipc == "host" },
		"Stop sharing the host IPC namespace with "+f.Service,
		"Delete `ipc: host`",
		"The container can no longer read or tamper with shared memory that host processes and other "+
			"containers use.",
		"If the service shares memory with a process on the host on purpose, that sharing stops; if it "+
			"only needs to share with one other container, `ipc: \"service:NAME\"` is the narrower setting.",
		func(d *compose.Doc, svc string) error { return d.RemoveKey(svc, "ipc") })
}

func buildRemoveHostUserns(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, func(s compose.Service) bool { return strings.EqualFold(strings.TrimSpace(s.UsernsMode), "host") },
		"Put "+f.Service+" back under user-namespace remapping",
		"Delete `userns_mode: host`",
		"Root inside the container maps to an unprivileged host UID again, so a container escape no "+
			"longer lands as host root.",
		"Files on bind mounts that were written as host root become unreadable to the remapped root, "+
			"which can stop a database or anything else that owns its data directory from starting.",
		func(d *compose.Doc, svc string) error { return d.RemoveKey(svc, "userns_mode") })
}

func hasSecurityOpt(opt string) func(compose.Service) bool {
	return func(s compose.Service) bool {
		for _, o := range s.SecurityOpt {
			if strings.EqualFold(strings.ReplaceAll(o, " ", ""), opt) {
				return true
			}
		}
		return false
	}
}

func buildRemoveSeccompUnconfined(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, hasSecurityOpt("seccomp:unconfined"),
		"Restore the seccomp filter for "+f.Service,
		"Remove `seccomp:unconfined` from security_opt",
		"Docker's default syscall filter applies again, blocking the kernel interfaces a container "+
			"escape usually goes through.",
		"Someone disabled the filter for a reason — usually one syscall an application needs, such as "+
			"a browser sandbox or a FUSE mount. That call will now fail with EPERM; if it does, a profile "+
			"allowing just that syscall is the narrow fix.",
		func(d *compose.Doc, svc string) error { return d.RemoveSecurityOpt(svc, "seccomp:unconfined") })
}

func buildRemoveAppArmorUnconfined(f model.Finding) (Fix, error) {
	return riskyComposeFix(f, hasSecurityOpt("apparmor:unconfined"),
		"Restore the AppArmor profile for "+f.Service,
		"Remove `apparmor:unconfined` from security_opt",
		"Docker's default AppArmor profile confines the container again, putting back a host-enforced "+
			"limit on what a compromise inside it can read and execute.",
		"If the service mounts filesystems or writes under /proc or /sys, the default profile will deny "+
			"it and the service will fail where it does that.",
		func(d *compose.Doc, svc string) error { return d.RemoveSecurityOpt(svc, "apparmor:unconfined") })
}

func hasVolume(source string, writable bool) func(compose.Service) bool {
	want := strings.TrimSuffix(source, "/")
	return func(s compose.Service) bool {
		for _, v := range s.Volumes {
			if strings.TrimSuffix(v.Source, "/") == want && (!writable || !v.ReadOnly) {
				return true
			}
		}
		return false
	}
}

func buildRemoveDockerSocket(f model.Finding) (Fix, error) {
	mount := f.Evidence["mount"]
	if mount == "" {
		return Fix{}, fmt.Errorf("finding %s has no mount to remove", f.ID)
	}
	return riskyComposeFix(f, hasVolume(mount, false),
		"Unmount the Docker socket from "+f.Service,
		"Remove the "+mount+" volume",
		"The container loses the Docker API, which is root on the host for anything that can reach it — "+
			"so compromising this service stops meaning compromising the machine.",
		"Portainer, Traefik's Docker provider, Watchtower and similar tools exist to talk to that API "+
			"and stop working without it. If this is one of them, a socket proxy that allows only the "+
			"calls it needs is the way to keep it working.",
		func(d *compose.Doc, svc string) error { return d.RemoveVolume(svc, mount) })
}

func buildMountReadOnly(f model.Finding) (Fix, error) {
	mount := f.Evidence["mount"]
	if mount == "" {
		return Fix{}, fmt.Errorf("finding %s has no mount to make read-only", f.ID)
	}
	return riskyComposeFix(f, hasVolume(mount, true),
		"Mount "+mount+" read-only in "+f.Service,
		"Add `:ro` to the "+mount+" mount",
		"A compromise of this container can still read "+mount+" but can no longer plant SSH keys, cron "+
			"jobs or anything else there to persist on the host.",
		"If the service writes under that mount — a backup tool restoring files, a config manager — those "+
			"writes start failing with a read-only filesystem error.",
		func(d *compose.Doc, svc string) error { return d.SetVolumeReadOnly(svc, mount) })
}

// readOnlyTmpfs are the paths nearly every image writes at runtime. Mounting
// them as tmpfs is what makes read_only survivable for most services; it is
// not a guarantee for any particular one.
var readOnlyTmpfs = []string{"/tmp", "/run"}

func buildReadOnlyRootfs(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	return Fix{
		Label:          "Make " + svc + "'s filesystem read-only",
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{composeEdit(path,
			"Set read_only: true with tmpfs at "+strings.Join(readOnlyTmpfs, " and "),
			"A process that breaks in can no longer replace the container's own binaries or leave tools "+
				"behind in its filesystem; anything it writes outside the tmpfs mounts fails, and what it "+
				"writes inside them is gone at the next restart.",
			"Many images write somewhere other than "+strings.Join(readOnlyTmpfs, " and ")+" — a cache "+
				"directory, a PID file, logs — and fail to start, or fail later, on a read-only root. "+
				"Watch the logs after recreating it; each path it complains about needs a tmpfs or a "+
				"volume. "+rollbackNote+" "+recreateNote(svc),
			svc,
			func(d *compose.Doc) error { return d.SetReadOnlyRootfs(svc, readOnlyTmpfs) })},
	}, nil
}

// nonRootUsers are the alternatives for ds009. hostveil cannot see what UID
// an image supports, so these are the two conventions an image is most likely
// to be built around, with the one an image's own non-root user usually has
// first.
var nonRootUsers = []struct{ value, why string }{
	{"1000:1000", "the first regular user, which most images that support a non-root user are built for"},
	{"65534:65534", "nobody, for a service that writes nothing it needs to own"},
}

func buildRunAsNonRoot(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	warning := "Images that start as root to set up and then drop privileges themselves — postgres " +
		"chowning its data directory, nginx binding port 80 — fail to start when a user is forced on " +
		"them, and files already on a volume stay owned by whoever wrote them. Check the image's " +
		"documentation for the UID it expects. " + rollbackNote + " " + recreateNote(svc)
	benefit := "A process that escapes this container lands on the host as an unprivileged UID instead of root."
	actions := make([]Action, 0, len(nonRootUsers))
	for _, u := range nonRootUsers {
		actions = append(actions, composeEdit(path,
			fmt.Sprintf("Run %s as %s — %s", svc, u.value, u.why), benefit, warning, svc,
			func(d *compose.Doc) error { return d.SetScalar(svc, "user", u.value) }))
	}
	return Fix{
		Label:          "Run " + svc + " as a non-root user",
		Kind:           model.RemediationReview,
		IndividualOnly: true,
		Actions:        actions,
	}, nil
}
