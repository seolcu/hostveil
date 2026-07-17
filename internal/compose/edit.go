package compose

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Doc is a mutable, comment-preserving view of a compose file used by
// fixes. Every mutation operates in memory; callers render back to bytes
// with Bytes() and decide when (or whether) to write. This is what lets
// fix previews compute an exact diff without ever touching the live file.
type Doc struct {
	root *yaml.Node // document node
}

// Load parses compose bytes into an editable Doc, preserving comments and
// formatting as far as yaml.v3 allows.
func Load(data []byte) (*Doc, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("empty compose document")
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("compose file is not a YAML mapping")
	}
	return &Doc{root: &root}, nil
}

// Bytes renders the (possibly mutated) document back to YAML.
func (d *Doc) Bytes() ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(d.root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// service returns the mapping node for a named service, or nil.
func (d *Doc) service(name string) *yaml.Node {
	top := d.root.Content[0]
	services := mapGet(top, "services")
	if services == nil {
		return nil
	}
	return mapGet(services, name)
}

// AddSecurityOpt appends opt to a service's security_opt list, creating
// the list if needed. It is a no-op if opt is already present.
func (d *Doc) AddSecurityOpt(service, opt string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	seq := mapGet(svc, "security_opt")
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(svc, "security_opt", seq)
	}
	for _, item := range seq.Content {
		if normalizeOpt(item.Value) == normalizeOpt(opt) {
			return nil // already present
		}
	}
	seq.Content = append(seq.Content, scalar(opt))
	return nil
}

// SetScalar sets service.<key> to a scalar value, replacing any existing
// value.
func (d *Doc) SetScalar(service, key, value string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	mapSet(svc, key, scalar(value))
	return nil
}

// BindPortLoopback rewrites a published port whose host port matches
// hostPort so it binds to 127.0.0.1 instead of all interfaces. It handles
// both short ("6379:6379") and long-form port entries.
func (d *Doc) BindPortLoopback(service, hostPort string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	ports := mapGet(svc, "ports")
	if ports == nil {
		return fmt.Errorf("service %q has no ports", service)
	}
	for _, entry := range ports.Content {
		switch entry.Kind {
		case yaml.ScalarNode:
			if rewritten, ok := rewriteShortPort(entry.Value, hostPort); ok {
				entry.Value = rewritten
				entry.Style = yaml.DoubleQuotedStyle
				return nil
			}
		case yaml.MappingNode:
			if hp := mapGet(entry, "published"); hp != nil && strings.Trim(hp.Value, `"`) == hostPort {
				mapSet(entry, "host_ip", scalar("127.0.0.1"))
				return nil
			}
		}
	}
	return fmt.Errorf("port %s not found on service %q", hostPort, service)
}

// rewriteShortPort turns "6379:6379" or "0.0.0.0:6379:6379" into
// "127.0.0.1:6379:6379" when the host port matches. Returns ok=false if
// the entry does not match or is already loopback-bound.
func rewriteShortPort(value, hostPort string) (string, bool) {
	proto := ""
	base := value
	if i := strings.LastIndex(value, "/"); i >= 0 {
		base, proto = value[:i], value[i:]
	}
	parts := strings.Split(base, ":")
	switch len(parts) {
	case 2:
		if parts[0] != hostPort {
			return "", false
		}
		return "127.0.0.1:" + parts[0] + ":" + parts[1] + proto, true
	case 3:
		if parts[1] != hostPort {
			return "", false
		}
		if parts[0] == "127.0.0.1" || parts[0] == "localhost" {
			return "", false // already loopback
		}
		return "127.0.0.1:" + parts[1] + ":" + parts[2] + proto, true
	default:
		return "", false
	}
}

// --- yaml.Node helpers ---

// mapGet returns the value node for key in a mapping node, or nil.
func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapSet sets key to val in a mapping node, replacing an existing value or
// appending a new key/value pair.
func mapSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, scalar(key), val)
}

func scalar(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func normalizeOpt(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "")
}
