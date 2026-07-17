// Package compose parses Docker Compose files into a typed model the
// compose checker inspects. It handles both the short and long forms of
// ports and volumes so detection logic never has to. Parsing is
// read-only; mutation for fixes lives in a later layer.
package compose

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Project is one Docker Compose project: a name, the file it was parsed
// from, and its services.
type Project struct {
	Name     string
	File     string
	Services map[string]Service
}

// Service is the subset of a compose service definition hostveil audits.
type Service struct {
	Name        string
	Image       string            `yaml:"image"`
	Privileged  bool              `yaml:"privileged"`
	ReadOnly    bool              `yaml:"read_only"`
	Pid         string            `yaml:"pid"`
	Ipc         string            `yaml:"ipc"`
	UsernsMode  string            `yaml:"userns_mode"`
	NetworkMode string            `yaml:"network_mode"`
	User        string            `yaml:"user"`
	Restart     string            `yaml:"restart"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Ports       []Port            `yaml:"ports"`
	Volumes     []Volume          `yaml:"volumes"`
	Environment Environment       `yaml:"environment"`
	EnvFile     StringOrList      `yaml:"env_file"`
	Healthcheck *yaml.Node        `yaml:"healthcheck"`
	Deploy      *Deploy           `yaml:"deploy"`
	MemLimit    string            `yaml:"mem_limit"`
	CPUs        string            `yaml:"cpus"`
	Labels      map[string]string `yaml:"-"`
}

// Deploy carries the resource limits hostveil checks for.
type Deploy struct {
	Resources struct {
		Limits struct {
			Memory string `yaml:"memory"`
			CPUs   string `yaml:"cpus"`
		} `yaml:"limits"`
	} `yaml:"resources"`
}

// Port is a normalized published-port mapping. Published is false for a
// container-only port (short form with just a container port).
type Port struct {
	HostIP        string
	HostPort      string
	ContainerPort string
	Protocol      string
	Published     bool
}

// ExposedOnAllInterfaces reports whether the port is reachable from any
// network interface (0.0.0.0 / :: / unset host IP with a published port),
// as opposed to bound to loopback only.
func (p Port) ExposedOnAllInterfaces() bool {
	if !p.Published {
		return false
	}
	switch p.HostIP {
	case "", "0.0.0.0", "::", "[::]":
		return true
	default:
		return false
	}
}

// UnmarshalYAML handles both short ("8080:80", "127.0.0.1:8080:80/tcp")
// and long (mapping with target/published/host_ip) port syntax.
func (p *Port) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return p.parseShort(node.Value)
	case yaml.MappingNode:
		var long struct {
			Target    int    `yaml:"target"`
			Published string `yaml:"published"`
			HostIP    string `yaml:"host_ip"`
			Protocol  string `yaml:"protocol"`
		}
		if err := node.Decode(&long); err != nil {
			return err
		}
		p.ContainerPort = strconv.Itoa(long.Target)
		p.HostPort = long.Published
		p.HostIP = long.HostIP
		p.Protocol = long.Protocol
		// A long-form entry with a published port is a host mapping.
		p.Published = long.Published != ""
		return nil
	default:
		return fmt.Errorf("unsupported port node kind %d", node.Kind)
	}
}

func (p *Port) parseShort(s string) error {
	if proto, rest, ok := cutLast(s, "/"); ok {
		p.Protocol = rest
		s = proto
	}
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		// container-only, e.g. "80" — not published to the host.
		p.ContainerPort = parts[0]
		p.Published = false
	case 2:
		// HOST:CONTAINER — published on all interfaces.
		p.HostPort = parts[0]
		p.ContainerPort = parts[1]
		p.Published = true
	case 3:
		// IP:HOST:CONTAINER
		p.HostIP = parts[0]
		p.HostPort = parts[1]
		p.ContainerPort = parts[2]
		p.Published = true
	default:
		return fmt.Errorf("cannot parse port %q", s)
	}
	return nil
}

// Volume is a normalized volume mount. Bind is true for a host-path bind
// mount (source starts with / or .), false for a named volume.
type Volume struct {
	Source   string
	Target   string
	ReadOnly bool
	Bind     bool
}

// UnmarshalYAML handles short ("src:dst:ro") and long (mapping) volume
// syntax.
func (v *Volume) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return v.parseShort(node.Value)
	case yaml.MappingNode:
		var long struct {
			Type     string `yaml:"type"`
			Source   string `yaml:"source"`
			Target   string `yaml:"target"`
			ReadOnly bool   `yaml:"read_only"`
		}
		if err := node.Decode(&long); err != nil {
			return err
		}
		v.Source = long.Source
		v.Target = long.Target
		v.ReadOnly = long.ReadOnly
		v.Bind = long.Type == "bind" || strings.HasPrefix(long.Source, "/") || strings.HasPrefix(long.Source, ".")
		return nil
	default:
		return fmt.Errorf("unsupported volume node kind %d", node.Kind)
	}
}

func (v *Volume) parseShort(s string) error {
	parts := strings.Split(s, ":")
	switch len(parts) {
	case 1:
		v.Target = parts[0]
	case 2:
		v.Source = parts[0]
		v.Target = parts[1]
	default:
		v.Source = parts[0]
		v.Target = parts[1]
		v.ReadOnly = parts[2] == "ro" || strings.Contains(parts[2], "ro")
	}
	v.Bind = strings.HasPrefix(v.Source, "/") || strings.HasPrefix(v.Source, ".")
	return nil
}

// Environment holds service environment variables, accepting both the
// map ({KEY: val}) and list (["KEY=val"]) compose forms.
type Environment map[string]string

// UnmarshalYAML normalizes both environment forms into a map.
func (e *Environment) UnmarshalYAML(node *yaml.Node) error {
	out := Environment{}
	switch node.Kind {
	case yaml.MappingNode:
		raw := map[string]string{}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		for k, v := range raw {
			out[k] = v
		}
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		for _, item := range list {
			if k, v, ok := strings.Cut(item, "="); ok {
				out[k] = v
			} else {
				out[item] = ""
			}
		}
	}
	*e = out
	return nil
}

// StringOrList accepts a scalar or list of strings (e.g. env_file).
type StringOrList []string

// UnmarshalYAML normalizes a scalar or sequence into a slice.
func (s *StringOrList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		*s = []string{node.Value}
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		*s = list
	}
	return nil
}

// ParseFile reads and parses a compose file at path into a Project. The
// project name defaults to the parent directory name.
func ParseFile(path string) (Project, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from docker compose ls
	if err != nil {
		return Project{}, err
	}
	return Parse(path, data)
}

// Parse parses compose file bytes into a Project.
func Parse(path string, data []byte) (Project, error) {
	var raw struct {
		Services map[string]Service `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Project{}, fmt.Errorf("parse %s: %w", path, err)
	}
	proj := Project{File: path, Services: map[string]Service{}}
	for name, svc := range raw.Services {
		svc.Name = name
		proj.Services[name] = svc
	}
	return proj, nil
}

// cutLast splits s at the last occurrence of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}
