// Package compose provides YAML editing primitives for Docker Compose files.
package compose

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	path     string
	doc      yaml.Node
	original []byte
	dirty    bool
}

func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("yaml parse: %w", err)
	}
	return &File{path: path, doc: doc, original: data}, nil
}

func (f *File) Backup() error {
	return os.WriteFile(f.path+".bak", f.original, 0644)
}

func (f *File) Save() error {
	if !f.dirty {
		return nil
	}
	out, err := yaml.Marshal(&f.doc)
	if err != nil {
		return err
	}
	return os.WriteFile(f.path, out, 0644)
}

func (f *File) Diff() string {
	tmp, _ := os.CreateTemp("", "hostveil-*.yml")
	defer os.Remove(tmp.Name())
	yaml.NewEncoder(tmp).Encode(&f.doc)
	tmp.Close()
	out, err := exec.Command("diff", "-u", f.path+".bak", tmp.Name()).CombinedOutput()
	if err == nil {
		return ""
	}
	return string(out)
}

func (f *File) SetField(service, path string, value interface{}) error {
	svc, err := f.serviceNode(service, true)
	if err != nil {
		return err
	}
	parts := strings.Split(path, ".")
	if err := setNested(svc, parts, value); err != nil {
		return err
	}
	f.dirty = true
	return nil
}

func (f *File) DeleteField(service, path string) error {
	svc, err := f.serviceNode(service, false)
	if err != nil {
		return err
	}
	if svc == nil {
		return nil
	}
	parts := strings.Split(path, ".")
	if err := deleteNested(svc, parts); err != nil {
		return err
	}
	f.dirty = true
	return nil
}

func (f *File) RemoveFromList(service, path string, value interface{}) error {
	svc, err := f.serviceNode(service, false)
	if err != nil {
		return err
	}
	if svc == nil {
		return nil
	}
	parts := strings.Split(path, ".")
	if err := removeFromListNested(svc, parts, fmt.Sprint(value)); err != nil {
		return err
	}
	f.dirty = true
	return nil
}

func (f *File) serviceNode(service string, create bool) (*yaml.Node, error) {
	// doc is DocumentNode, Content[0] is the root mapping
	root := f.doc.Content[0]
	if root == nil {
		if !create {
			return nil, nil
		}
		root = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		f.doc.Content = append(f.doc.Content, root)
	}

	services := getOrCreateMappingEntry(root, "services", create)
	if services == nil {
		return nil, nil
	}
	svc := getOrCreateMappingEntry(services, service, create)
	return svc, nil
}

func getOrCreateMappingEntry(mapping *yaml.Node, key string, create bool) *yaml.Node {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	if !create {
		return nil
	}
	if mapping.Kind != yaml.MappingNode {
		mapping.Kind = yaml.MappingNode
		mapping.Tag = "!!map"
	}
	kn := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	vn := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapping.Content = append(mapping.Content, kn, vn)
	return vn
}

func findInMapping(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func setNested(parent *yaml.Node, parts []string, value interface{}) error {
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		insertOrUpdateEntry(parent, parts[0], toNode(value))
		return nil
	}
	next := findInMapping(parent, parts[0])
	if next == nil {
		next = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		insertOrUpdateEntry(parent, parts[0], next)
	}
	return setNested(next, parts[1:], value)
}

func deleteNested(parent *yaml.Node, parts []string) error {
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		deleteEntry(parent, parts[0])
		return nil
	}
	next := findInMapping(parent, parts[0])
	if next == nil {
		return nil
	}
	return deleteNested(next, parts[1:])
}

func removeFromListNested(parent *yaml.Node, parts []string, value string) error {
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		removeSequenceEntry(parent, parts[0], value)
		return nil
	}
	next := findInMapping(parent, parts[0])
	if next == nil {
		return nil
	}
	return removeFromListNested(next, parts[1:], value)
}

func insertOrUpdateEntry(mapping *yaml.Node, key string, val *yaml.Node) {
	if mapping.Kind != yaml.MappingNode {
		mapping.Kind = yaml.MappingNode
		mapping.Tag = "!!map"
		mapping.Content = nil
	}
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content[i+1] = val
			return
		}
	}
	kn := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	mapping.Content = append(mapping.Content, kn, val)
}

func deleteEntry(mapping *yaml.Node, key string) {
	for i := 0; i < len(mapping.Content)-1; i += 2 {
		if mapping.Content[i].Value == key {
			mapping.Content = append(mapping.Content[:i], mapping.Content[i+2:]...)
			return
		}
	}
}

func removeSequenceEntry(mapping *yaml.Node, key string, value string) {
	seq := findInMapping(mapping, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return
	}
	var kept []*yaml.Node
	for _, item := range seq.Content {
		if item.Value != value {
			kept = append(kept, item)
		}
	}
	seq.Content = kept
}

func toNode(v interface{}) *yaml.Node {
	n := &yaml.Node{}
	switch val := v.(type) {
	case bool:
		n.Kind = yaml.ScalarNode
		n.Tag = "!!bool"
		n.Value = strconv.FormatBool(val)
	case int:
		n.Kind = yaml.ScalarNode
		n.Tag = "!!int"
		n.Value = strconv.Itoa(val)
	case float64:
		n.Kind = yaml.ScalarNode
		n.Tag = "!!float"
		n.Value = strconv.FormatFloat(val, 'f', -1, 64)
	case string:
		n.Kind = yaml.ScalarNode
		n.Tag = "!!str"
		n.Value = val
	case []interface{}:
		n.Kind = yaml.SequenceNode
		n.Tag = "!!seq"
		for _, item := range val {
			n.Content = append(n.Content, toNode(item))
		}
	case map[string]interface{}:
		n.Kind = yaml.MappingNode
		n.Tag = "!!map"
		for k, v := range val {
			n.Content = append(n.Content, toNode(k), toNode(v))
		}
	default:
		n.Kind = yaml.ScalarNode
		n.Tag = "!!str"
		n.Value = fmt.Sprint(v)
	}
	return n
}

func (f *File) ServiceNames() ([]string, error) {
	root := f.doc.Content[0]
	if root == nil {
		return nil, nil
	}
	services := findInMapping(root, "services")
	if services == nil {
		return nil, nil
	}
	var names []string
	for i := 0; i < len(services.Content)-1; i += 2 {
		names = append(names, services.Content[i].Value)
	}
	return names, nil
}

func (f *File) GetFieldStrings(service, path string) ([]string, error) {
	svc, err := f.serviceNode(service, false)
	if err != nil || svc == nil {
		return nil, err
	}
	parts := strings.Split(path, ".")
	node := svc
	for _, part := range parts {
		node = findInMapping(node, part)
		if node == nil {
			return nil, nil
		}
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return []string{node.Value}, nil
	case yaml.SequenceNode:
		var vals []string
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				vals = append(vals, item.Value)
			}
		}
		return vals, nil
	default:
		return nil, nil
	}
}

func (f *File) GetFieldRaw(service, path string) (string, error) {
	svc, err := f.serviceNode(service, false)
	if err != nil || svc == nil {
		return "", err
	}
	parts := strings.Split(path, ".")
	node := svc
	for _, part := range parts {
		node = findInMapping(node, part)
		if node == nil {
			return "", nil
		}
	}
	if node.Kind == yaml.ScalarNode {
		return node.Value, nil
	}
	return "", nil
}
