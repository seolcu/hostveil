package platform

import (
	"strings"
	"testing"
)

// The rule, over the runtimes this build will not be running under. Each case
// is the marker that runtime actually leaves, which is the whole reason the
// evidence is a value rather than four reads inlined into the decision.
func TestContainerRuntimeReadsEachRuntimesOwnMarker(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence ContainerEvidence
		want     bool
		says     string
	}{
		{
			name:     "docker",
			evidence: ContainerEvidence{DockerEnv: true},
			want:     true, says: "/.dockerenv",
		},
		{
			name:     "podman writes both",
			evidence: ContainerEvidence{ContainerEnv: true, InitEnviron: "container=podman\x00PATH=/usr/bin"},
			want:     true, says: "/run/.containerenv",
		},
		{
			name:     "systemd-nspawn names itself on pid 1",
			evidence: ContainerEvidence{InitEnviron: "PATH=/usr/bin\x00container=systemd-nspawn\x00"},
			want:     true, says: "systemd-nspawn",
		},
		{
			name:     "lxc names itself on pid 1",
			evidence: ContainerEvidence{InitEnviron: "container=lxc\x00"},
			want:     true, says: "lxc",
		},
		{
			name:     "cgroup v1 path, no other marker",
			evidence: ContainerEvidence{InitCgroup: "12:pids:/docker/3b8f1e\n11:cpu:/docker/3b8f1e\n"},
			want:     true, says: "cgroup",
		},
		{
			name:     "kubernetes",
			evidence: ContainerEvidence{InitCgroup: "0::/kubepods/besteffort/pod9f/2a1b\n"},
			want:     true, says: "cgroup",
		},
		{
			name:     "an ordinary host",
			evidence: ContainerEvidence{InitEnviron: "PATH=/usr/bin\x00HOME=/root\x00", InitCgroup: "0::/init.scope\n"},
			want:     false,
		},
		{
			name:     "a host with nothing readable about pid 1",
			evidence: ContainerEvidence{},
			want:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, why := containerRuntime(tc.evidence)
			if got != tc.want {
				t.Fatalf("containerRuntime = %v (%q), want %v", got, why, tc.want)
			}
			if !got {
				if why != "" {
					t.Errorf("a host must carry no reason, got %q", why)
				}
				return
			}
			if !strings.Contains(why, tc.says) {
				t.Errorf("reason %q does not name %q; a skip the operator cannot act on "+
					"is the thing this gate is supposed to replace", why, tc.says)
			}
		})
	}
}

// The one that matters most, and the reason the cgroup markers are anchored
// rather than loose.
//
// A host running Docker has cgroup paths full of the word "container", and pid
// 1 is systemd's init.scope. Matching "container" anywhere would call every
// Docker host a container and skip the firewall domain on exactly the machines
// this program is written for — which is a far worse failure than the one being
// fixed, because it is silent and it is on the common path.
func TestADockerHostIsNotAContainer(t *testing.T) {
	for _, cgroup := range []string{
		"0::/init.scope\n",
		"0::/system.slice/containerd.service\n", // the daemon, running on the host
		"0::/system.slice/docker.service\n",
		"11:name=systemd:/user.slice/user-1000.slice/session-3.scope\n",
	} {
		if got, why := containerRuntime(ContainerEvidence{InitCgroup: cgroup}); got {
			t.Errorf("cgroup %q read as a container (%q)", strings.TrimSpace(cgroup), why)
		}
	}
}

// HOSTVEIL_ASSUME_HOST is the documented opt-out, and it has to reach the
// exported entry point rather than the rule — the rule is about evidence, and
// the override is about what the operator is telling us to do with it.
func TestAssumeHostOptsOutOfTheGate(t *testing.T) {
	t.Setenv(AssumeHostEnv, "1")
	if got, why := ContainerRuntime(); got {
		t.Errorf("ContainerRuntime = true (%q) with %s set", why, AssumeHostEnv)
	}
}

// And it is off by default, so the gate cannot be disabled by accident.
func TestTheGateIsOnWithoutTheOptOut(t *testing.T) {
	t.Setenv(AssumeHostEnv, "")
	// No assertion on the result — this build may or may not be in a
	// container. The assertion is that the override is not what decided it.
	if _, why := ContainerRuntime(); strings.Contains(why, AssumeHostEnv) {
		t.Errorf("unexpected reason %q", why)
	}
}
