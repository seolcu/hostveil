package compose

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// GetEnvironment returns environment key/value pairs for a service. Supports
// map syntax and list syntax ("KEY=VALUE" or "KEY: VALUE").
func (f *File) GetEnvironment(service string) map[string]string {
	node := f.walkPath(service, "environment")
	if node == nil {
		return nil
	}
	out := make(map[string]string)
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			valNode := node.Content[i+1]
			if valNode.Kind == yaml.ScalarNode {
				out[key] = valNode.Value
			}
		}
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			key, val, ok := splitEnvEntry(item.Value)
			if ok {
				out[key] = val
			}
		}
	case yaml.ScalarNode:
		if key, val, ok := splitEnvEntry(node.Value); ok {
			out[key] = val
		}
	}
	return out
}

func splitEnvEntry(entry string) (key, val string, ok bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", "", false
	}
	if idx := strings.Index(entry, "="); idx > 0 {
		return entry[:idx], entry[idx+1:], true
	}
	if idx := strings.Index(entry, ":"); idx > 0 {
		return strings.TrimSpace(entry[:idx]), strings.TrimSpace(entry[idx+1:]), true
	}
	return "", "", false
}

// SetEnvironmentValue sets or updates one environment variable for a service.
func (f *File) SetEnvironmentValue(service, key, value string) error {
	svc, err := f.serviceNode(service, true)
	if err != nil {
		return err
	}
	env := findInMapping(svc, "environment")
	if env == nil {
		env = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		insertOrUpdateEntry(svc, "environment", env)
	}
	if env.Kind == yaml.SequenceNode {
		for _, item := range env.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			existingKey, _, ok := splitEnvEntry(item.Value)
			if ok && existingKey == key {
				item.Value = key + "=" + value
				f.dirty = true
				return nil
			}
		}
		env.Content = append(env.Content, &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   "!!str",
			Value: key + "=" + value,
		})
		f.dirty = true
		return nil
	}
	if env.Kind != yaml.MappingNode {
		env.Kind = yaml.MappingNode
		env.Tag = "!!map"
		env.Content = nil
	}
	insertOrUpdateEntry(env, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	f.dirty = true
	return nil
}

// DeleteEnvironmentKey removes one environment variable from a service.
func (f *File) DeleteEnvironmentKey(service, key string) error {
	svc, err := f.serviceNode(service, false)
	if err != nil || svc == nil {
		return nil
	}
	env := findInMapping(svc, "environment")
	if env == nil {
		return nil
	}
	switch env.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(env.Content)-1; i += 2 {
			if env.Content[i].Value == key {
				env.Content = append(env.Content[:i], env.Content[i+2:]...)
				f.dirty = true
				return nil
			}
		}
	case yaml.SequenceNode:
		var kept []*yaml.Node
		for _, item := range env.Content {
			if item.Kind != yaml.ScalarNode {
				kept = append(kept, item)
				continue
			}
			existingKey, _, ok := splitEnvEntry(item.Value)
			if ok && existingKey == key {
				f.dirty = true
				continue
			}
			kept = append(kept, item)
		}
		env.Content = kept
	}
	return nil
}
