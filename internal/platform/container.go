package platform

import (
	"os"
	"strings"
)

// AssumeHostEnv makes hostveil treat this filesystem as a host even when it is
// plainly a container.
//
// It exists for one honest use: a disposable container used *as* a host
// filesystem, which is what .github/workflows/e2e.yml does and says it does —
// "A container gives a disposable root filesystem." That job writes
// /etc/ssh/sshd_config and chmods files under /etc precisely because doing it
// to the runner would be rude and unrepeatable, and the domains gated below
// are ones it means to exercise.
//
// It is not a way to make an inconvenient finding go away. Everything the gate
// suppresses is suppressed because it cannot be acted on from inside a
// container, and setting this does not change that — it only changes who is
// told.
const AssumeHostEnv = "HOSTVEIL_ASSUME_HOST"

// ContainerRuntime reports whether this process is running inside a container,
// and names the evidence when it is.
//
// This is AuditableOS's question asked about a different environment, and it
// is here for the same reason: it is a statement about what host this is, not
// about any one tool, and three checkers making the same call three ways is
// how the macOS version of this bug survived as long as it did.
//
// What a container breaks:
//
//   - The firewall domain probes ufw, firewall-cmd, nft and iptables. A
//     container has none of them and never will; the packet filter that
//     decides whether its ports answer belongs to the host and is invisible
//     from inside. probe therefore returns StatusInactive, Check reports "no
//     active host firewall" at the top severity, and the finding is noise on
//     every container that has ever run it. Verified on bare Fedora and Alpine
//     images: both scored the firewall axis 50/100 on a fabricated High.
//   - The sysctl domain reads /proc/sys, which for a non-namespaced knob —
//     kernel.kptr_restrict, kernel.dmesg_restrict — is the *host* kernel's
//     value. The reading is true. The fix is not: writing /etc/sysctl.d inside
//     a container cannot change the host kernel however many times
//     `sysctl --system` runs, so the file appears, the fix reports success, a
//     checkpoint is recorded, and the value never moves. internal/fix/sysctl.go
//     already calls that the worst available outcome and declines it for a
//     drop-in under /usr or /run; this is the same refusal for the same reason.
//
// Both are reachable through instructions this project publishes: the README
// and the measured-results page tell people to try it "on a container or a
// throwaway VM rather than your own machine", and `fix --all --review` — which
// scripts/measure/run.sh runs — applies the sysctl fixes.
func ContainerRuntime() (bool, string) {
	if os.Getenv(AssumeHostEnv) != "" {
		return false, ""
	}
	return containerRuntime(readContainerEvidence())
}

// ContainerEvidence is what the filesystem says about being a container. It is
// a separate type so the rule below is pure and can be table-tested for
// runtimes this build will never run under — the same reason auditableOS takes
// its goos as an argument.
type ContainerEvidence struct {
	// DockerEnv is whether /.dockerenv exists. Docker has created it since
	// forever and it is the single most reliable marker there is.
	DockerEnv bool
	// ContainerEnv is whether /run/.containerenv exists, which is Podman's
	// equivalent and is also written by Buildah.
	ContainerEnv bool
	// InitEnviron is /proc/1/environ verbatim, NUL-separated. systemd-nspawn,
	// Podman and LXC all set container=<name> for pid 1.
	InitEnviron string
	// InitCgroup is /proc/1/cgroup verbatim. On cgroup v1 the runtime's name
	// appears in the path; on v2 it usually does not, which is why this is the
	// last resort rather than the first.
	InitCgroup string
}

// cgroupMarkers are runtime names that appear in a cgroup path only inside a
// container. Deliberately not "container", which appears in ordinary paths on
// a host running containers — pid 1 of the *host* is not in one of them, but a
// substring test that loose is one rename away from calling every Docker host
// a container.
var cgroupMarkers = []string{"/docker/", "/docker-", "/lxc/", "/kubepods", "containerd.service/"}

func containerRuntime(e ContainerEvidence) (bool, string) {
	switch {
	case e.DockerEnv:
		return true, "this is a container (/.dockerenv)"
	case e.ContainerEnv:
		return true, "this is a container (/run/.containerenv)"
	}
	// container=<name> is set on pid 1 by the runtime itself, so it names the
	// runtime rather than being guessed from a path.
	for _, kv := range strings.Split(e.InitEnviron, "\x00") {
		if name, ok := strings.CutPrefix(kv, "container="); ok && name != "" {
			return true, "this is a " + name + " container"
		}
	}
	for _, m := range cgroupMarkers {
		if strings.Contains(e.InitCgroup, m) {
			return true, "this is a container (pid 1 is in " + strings.Trim(m, "/") + "'s cgroup)"
		}
	}
	return false, ""
}

// readContainerEvidence collects the observations. Every read is best-effort:
// /proc/1 is unreadable in a user namespace that does not own pid 1, and a
// missing file is simply evidence this runtime did not leave that marker.
func readContainerEvidence() ContainerEvidence {
	e := ContainerEvidence{}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		e.DockerEnv = true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		e.ContainerEnv = true
	}
	if b, err := os.ReadFile("/proc/1/environ"); err == nil {
		e.InitEnviron = string(b)
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		e.InitCgroup = string(b)
	}
	return e
}
