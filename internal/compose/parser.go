package compose

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

type rawCompose struct {
	Version  string                `yaml:"version"`
	Services map[string]rawService `yaml:"services"`
	Volumes  map[string]rawVolume  `yaml:"volumes"`
	Networks map[string]rawNetwork `yaml:"networks"`
}

type rawService struct {
	Image       string            `yaml:"image"`
	Container   string            `yaml:"container_name"`
	User        string            `yaml:"user"`
	Ports       []any             `yaml:"ports"`
	Volumes     []any             `yaml:"volumes"`
	Environment any               `yaml:"environment"`
	EnvFile     []string          `yaml:"env_file"`
	CapAdd      []string          `yaml:"cap_add"`
	CapDrop     []string          `yaml:"cap_drop"`
	Privileged  bool              `yaml:"privileged"`
	ReadOnly    bool              `yaml:"read_only"`
	NetworkMode string            `yaml:"network_mode"`
	Labels      map[string]string `yaml:"labels"`
	DependsOn   any               `yaml:"depends_on"`
	Restart     string            `yaml:"restart"`
	Command     string            `yaml:"command"`
}

type rawVolume struct {
	Driver string `yaml:"driver"`
}

type rawNetwork struct {
	Driver   string `yaml:"driver"`
	External any    `yaml:"external"`
}

func ParseFile(path string) (*ComposeFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read compose file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*ComposeFile, error) {
	var raw rawCompose
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse compose yaml: %w", err)
	}

	cf := &ComposeFile{
		Version:  raw.Version,
		Services: make(map[string]Service),
		Volumes:  make(map[string]Volume),
		Networks: make(map[string]Network),
	}

	for name, rs := range raw.Services {
		svc := Service{
			Image:       rs.Image,
			Container:   rs.Container,
			User:        rs.User,
			Privileged:  rs.Privileged,
			ReadOnly:    rs.ReadOnly,
			NetworkMode: rs.NetworkMode,
			Labels:      rs.Labels,
			Restart:     rs.Restart,
			Command:     rs.Command,
		}

		svc.Ports = parsePorts(rs.Ports)
		svc.Volumes = parseVolumes(rs.Volumes)
		svc.Environment = parseEnvironment(rs.Environment, name)
		svc.EnvFile = rs.EnvFile
		svc.CapAdd = rs.CapAdd
		svc.CapDrop = rs.CapDrop
		svc.DependsOn = parseDependsOn(rs.DependsOn)

		cf.Services[name] = svc
	}

	for name, rv := range raw.Volumes {
		cf.Volumes[name] = Volume{Driver: rv.Driver}
	}

	for name, rn := range raw.Networks {
		external := false
		if en, ok := rn.External.(bool); ok {
			external = en
		}
		cf.Networks[name] = Network{
			Driver:   rn.Driver,
			External: external,
		}
	}

	return cf, nil
}

func parsePorts(raw []any) []Port {
	var ports []Port
	for _, p := range raw {
		switch v := p.(type) {
		case string:
			port := parsePortString(v)
			if port != nil {
				ports = append(ports, *port)
			}
		case map[string]any:
			port := parsePortMap(v)
			if port != nil {
				ports = append(ports, *port)
			}
		}
	}
	return ports
}

func parsePortString(s string) *Port {
	// Format: "HOST:CONTAINER" or "HOST:CONTAINER/PROTO" or "IP:HOST:CONTAINER"
	parts := strings.Split(s, "/")
	proto := "tcp"
	if len(parts) > 1 {
		proto = parts[1]
	}

	hostPort := ""
	containerPort := ""
	hostIP := ""

	address := parts[0]
	if strings.Contains(address, ":") {
		segments := strings.Split(address, ":")
		if len(segments) == 3 {
			hostIP = segments[0]
			hostPort = segments[1]
			containerPort = segments[2]
		} else if len(segments) == 2 {
			hostPort = segments[0]
			containerPort = segments[1]
		}
	} else {
		containerPort = address
	}

	published, _ := strconv.ParseUint(hostPort, 10, 16)
	target, _ := strconv.ParseUint(containerPort, 10, 16)

	if target == 0 {
		return nil
	}

	return &Port{
		Published: uint16(published),
		Target:    uint16(target),
		Protocol:  proto,
		HostIP:    hostIP,
	}
}

func parsePortMap(m map[string]any) *Port {
	p := &Port{}
	if v, ok := m["published"]; ok {
		p.Published = toUint16(v)
	}
	if v, ok := m["target"]; ok {
		p.Target = toUint16(v)
	}
	if v, ok := m["protocol"]; ok {
		p.Protocol = fmt.Sprint(v)
	}
	if v, ok := m["host_ip"]; ok {
		p.HostIP = fmt.Sprint(v)
	}
	if p.Target == 0 {
		return nil
	}
	return p
}

func parseVolumes(raw []any) []VolumeMount {
	var vols []VolumeMount
	for _, v := range raw {
		switch val := v.(type) {
		case string:
			if vm := parseVolumeString(val); vm != nil {
				vols = append(vols, *vm)
			}
		case map[string]any:
			if vm := parseVolumeMap(val); vm != nil {
				vols = append(vols, *vm)
			}
		}
	}
	return vols
}

func parseVolumeString(s string) *VolumeMount {
	parts := strings.Split(s, ":")
	if len(parts) < 2 {
		return nil
	}
	vm := &VolumeMount{
		Source: parts[0],
		Target: parts[1],
	}
	if len(parts) > 2 && parts[2] == "ro" {
		vm.ReadOnly = true
	}
	return vm
}

func parseVolumeMap(m map[string]any) *VolumeMount {
	vm := &VolumeMount{}
	if v, ok := m["source"]; ok {
		vm.Source = fmt.Sprint(v)
	}
	if v, ok := m["target"]; ok {
		vm.Target = fmt.Sprint(v)
	}
	if v, ok := m["read_only"]; ok {
		vm.ReadOnly = toBool(v)
	}
	if vm.Source == "" || vm.Target == "" {
		return nil
	}
	return vm
}

func parseEnvironment(raw any, serviceName string) map[string]string {
	env := make(map[string]string)

	switch v := raw.(type) {
	case map[string]any:
		for key, val := range v {
			if val != nil {
				env[key] = fmt.Sprint(val)
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if parts := strings.SplitN(s, "=", 2); len(parts) == 2 {
					env[parts[0]] = parts[1]
				}
			}
		}
	}

	return env
}

func parseDependsOn(raw any) []string {
	switch v := raw.(type) {
	case []any:
		deps := make([]string, len(v))
		for i, d := range v {
			deps[i] = fmt.Sprint(d)
		}
		return deps
	case map[string]any:
		deps := make([]string, 0, len(v))
		for name := range v {
			deps = append(deps, name)
		}
		return deps
	default:
		return nil
	}
}

func toUint16(v any) uint16 {
	s := fmt.Sprint(v)
	n, _ := strconv.ParseUint(s, 10, 16)
	return uint16(n)
}

func toBool(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true") || val == "1"
	default:
		return false
	}
}
