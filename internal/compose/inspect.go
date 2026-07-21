package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
	"gopkg.in/yaml.v3"
)

// composeProjectLabel is set by Docker Compose on every container it creates.
// Its presence is how a container started by `docker run` is told apart from
// one this package already audits through its compose file.
const composeProjectLabel = "com.docker.compose.project"

// Container is a running container that no compose file describes, normalized
// into the same Service shape the compose rules already audit.
//
// The two are deliberately not interchangeable. A compose service can be
// fixed by editing its file; a container started with `docker run` has no
// file to edit, and its settings live only in the daemon's record of how it
// was created. Callers must not offer a file-editing fix for one of these.
type Container struct {
	// Name is the container name with Docker's leading slash removed.
	Name string
	// Service is the normalized view the audit rules consume.
	Service Service
}

// DiscoverContainers returns running containers that Docker Compose did not
// create.
//
// Without this the compose and CVE checkers see only what `docker compose ls`
// reports, so a hand-started `docker run -d --privileged -p 6379:6379 redis`
// — the most dangerous object likely to be on the box — produced no findings
// on either of the two highest-weighted axes. Those axes were not reporting
// "nothing wrong"; they were reporting on a subset of the containers and
// scoring as if it were all of them.
func DiscoverContainers(ctx context.Context, r platform.CommandRunner) ([]Container, error) {
	out, err := r.Run(ctx, "docker", "ps", "--quiet", "--no-trunc")
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil, nil
	}

	raw, err := r.Run(ctx, "docker", append([]string{"inspect"}, ids...)...)
	if err != nil {
		return nil, fmt.Errorf("inspect containers: %w", err)
	}
	return parseInspect(raw)
}

// dockerContainer is the subset of `docker inspect` output the rules need.
type dockerContainer struct {
	Name   string `json:"Name"`
	Config struct {
		Image       string            `json:"Image"`
		User        string            `json:"User"`
		Env         []string          `json:"Env"`
		Labels      map[string]string `json:"Labels"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		Privileged    bool                `json:"Privileged"`
		NetworkMode   string              `json:"NetworkMode"`
		PidMode       string              `json:"PidMode"`
		IpcMode       string              `json:"IpcMode"`
		CapAdd        []string            `json:"CapAdd"`
		SecurityOpt   []string            `json:"SecurityOpt"`
		Binds         []string            `json:"Binds"`
		Memory        int64               `json:"Memory"`
		PortBindings  map[string][]hostIP `json:"PortBindings"`
		RestartPolicy struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

type hostIP struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

func parseInspect(raw []byte) ([]Container, error) {
	var entries []dockerContainer
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse docker inspect: %w", err)
	}
	var out []Container
	for _, e := range entries {
		if e.Config.Labels[composeProjectLabel] != "" {
			continue // already audited through its compose file
		}
		name := strings.TrimPrefix(e.Name, "/")
		if name == "" {
			continue
		}
		out = append(out, Container{Name: name, Service: e.toService(name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// toService maps the daemon's record of a container onto the Service fields
// the rules read. Fields with no meaningful runtime equivalent are left zero
// and the caller skips the rules that depend on them — see the checker.
func (e dockerContainer) toService(name string) Service {
	s := Service{
		Name:        name,
		Image:       e.Config.Image,
		Privileged:  e.HostConfig.Privileged,
		NetworkMode: e.HostConfig.NetworkMode,
		Pid:         e.HostConfig.PidMode,
		Ipc:         e.HostConfig.IpcMode,
		User:        e.Config.User,
		Restart:     e.HostConfig.RestartPolicy.Name,
		CapAdd:      e.HostConfig.CapAdd,
		SecurityOpt: e.HostConfig.SecurityOpt,
		Ports:       inspectPorts(e.HostConfig.PortBindings),
		Volumes:     inspectVolumes(e.HostConfig.Binds),
	}
	// Docker reports "no restart policy" as the empty string on older
	// daemons and as "no" on newer ones; the rule already treats both as
	// unset, so no normalization is needed here.
	if e.Config.Healthcheck != nil && len(e.Config.Healthcheck.Test) > 0 {
		// The rule only tests this for nil. A container's healthcheck has no
		// YAML form to reproduce, and inventing one would be a lie about
		// where the setting came from, so a bare node stands for "present".
		s.Healthcheck = &yaml.Node{Kind: yaml.MappingNode}
	}
	if e.HostConfig.Memory > 0 {
		s.MemLimit = fmt.Sprintf("%d", e.HostConfig.Memory)
	}
	return s
}

// inspectPorts converts PortBindings ("6379/tcp" -> [{HostIp, HostPort}])
// into the normalized Port list. Only bindings with a host port are
// published; a container port with no binding is not reachable from the host.
func inspectPorts(bindings map[string][]hostIP) []Port {
	var ports []Port
	for spec, binds := range bindings {
		containerPort, proto, _ := strings.Cut(spec, "/")
		for _, b := range binds {
			if b.HostPort == "" {
				continue
			}
			ports = append(ports, Port{
				HostIP:        b.HostIP,
				HostPort:      b.HostPort,
				ContainerPort: containerPort,
				Protocol:      proto,
				Published:     true,
			})
		}
	}
	// Map iteration order is random and these ports reach a finding's
	// evidence, so a stable order keeps repeat scans from producing a delta
	// that reports a change nobody made.
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].HostPort != ports[j].HostPort {
			return ports[i].HostPort < ports[j].HostPort
		}
		return ports[i].HostIP < ports[j].HostIP
	})
	return ports
}

// inspectVolumes converts HostConfig.Binds ("/src:/dst:ro") into the
// normalized Volume list. Only bind mounts appear there; named volumes are
// listed under Mounts and are not host paths, so the sensitive-path rule
// has nothing to say about them.
func inspectVolumes(binds []string) []Volume {
	var vols []Volume
	for _, b := range binds {
		parts := strings.Split(b, ":")
		if len(parts) < 2 {
			continue
		}
		v := Volume{Source: parts[0], Target: parts[1]}
		// A source that starts with / is a host path; anything else is a
		// named volume, which cannot be a sensitive host directory.
		v.Bind = strings.HasPrefix(v.Source, "/")
		for _, opt := range parts[2:] {
			for _, o := range strings.Split(opt, ",") {
				if o == "ro" {
					v.ReadOnly = true
				}
			}
		}
		vols = append(vols, v)
	}
	return vols
}
