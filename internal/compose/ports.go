package compose

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// RestrictPortBindings rewrites exposed port entries so host-side bindings
// use bindIP instead of 0.0.0.0 or an implicit all-interfaces bind.
// Short-syntax scalars and long-syntax mapping entries are updated in place
// so mixed-syntax port lists keep their original form.
func (f *File) RestrictPortBindings(service, bindIP string) (bool, error) {
	node := f.walkPath(service, "ports")
	if node == nil || node.Kind != yaml.SequenceNode {
		return false, nil
	}
	changed := false
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			newV, ok := restrictPortScalar(item.Value, bindIP)
			if ok {
				item.Value = newV
				changed = true
			}
		case yaml.MappingNode:
			if restrictPortMapping(item, bindIP) {
				changed = true
			}
		}
	}
	if changed {
		f.dirty = true
	}
	return changed, nil
}

func restrictPortScalar(v, bindIP string) (string, bool) {
	if v == "" {
		return v, false
	}
	rest := v
	proto := ""
	if idx := strings.LastIndex(v, "/"); idx > 0 {
		rest = v[:idx]
		proto = v[idx:]
	}
	if !strings.Contains(rest, ":") {
		return v, false
	}
	firstColon := strings.Index(rest, ":")
	lastColon := strings.LastIndex(rest, ":")
	if firstColon == lastColon {
		return bindIP + ":" + rest + proto, true
	}
	secondColon := strings.Index(rest[firstColon+1:], ":") + firstColon + 1
	hostPort := rest[firstColon+1 : secondColon]
	containerPort := rest[secondColon+1:]
	if strings.Contains(hostPort, "-") || strings.Contains(containerPort, "-") {
		return v, false
	}
	hostIP := rest[:firstColon]
	if hostIP != "0.0.0.0" && hostIP != "" {
		return v, false
	}
	return bindIP + ":" + hostPort + ":" + containerPort + proto, true
}

func restrictPortMapping(item *yaml.Node, bindIP string) bool {
	fields := mappingFields(item)
	hostIP := fields["host_ip"]
	published := fields["published"]
	if published == "" {
		return false
	}
	if hostIP != "" && hostIP != "0.0.0.0" {
		return false
	}
	setMappingScalar(item, "host_ip", bindIP)
	return true
}

func setMappingScalar(mapping *yaml.Node, key, value string) {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			val := mapping.Content[i+1]
			val.Kind = yaml.ScalarNode
			val.Tag = "!!str"
			val.Value = value
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value},
	)
}
