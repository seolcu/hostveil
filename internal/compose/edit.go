package compose

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Doc is a mutable, comment-preserving view of a compose file used by
// fixes. Every mutation operates in memory; callers render back to bytes
// with Bytes() and decide when (or whether) to write. This is what lets
// fix previews compute an exact diff without ever touching the live file.
//
// Rendering favours a *minimal* text edit against the original source so a
// one-line change stays a one-line diff: re-encoding the whole document
// through yaml.v3 would otherwise reflow untouched lines (collapse aligned
// inline comments, drop blank lines between services). Each mutation records
// the text edit it makes; Bytes() applies those edits to the original bytes
// and only trusts the result when it is byte-for-byte equivalent to the
// encoder's output after a round-trip — otherwise it falls back to the
// full re-encode, so correctness never depends on the text surgery.
type Doc struct {
	root       *yaml.Node // document node
	src        []byte     // original source, for minimal-diff rendering
	edits      []edit     // recorded text edits, in application order
	minimalOff bool       // a mutation could not be expressed as a text edit
}

type editKind int

const (
	editReplace editKind = iota // replace a scalar value in place on one line
	editInsert                  // insert whole line(s) after an anchor line
)

type edit struct {
	kind editKind
	line int    // 1-based anchor line in the original source
	col  int    // 1-based start column of the value (editReplace only)
	text string // replacement token (editReplace) or lines to insert (editInsert)
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
	return &Doc{root: &root, src: append([]byte(nil), data...)}, nil
}

// Bytes renders the (possibly mutated) document back to YAML. It prefers a
// minimal text edit of the original source and falls back to a full re-encode
// whenever the minimal result is not provably equivalent.
func (d *Doc) Bytes() ([]byte, error) {
	full, err := encodeNode(d.root)
	if err != nil {
		return nil, err
	}
	if d.minimalOff || len(d.edits) == 0 {
		return full, nil
	}
	minimal, ok := d.renderMinimal()
	if !ok {
		return full, nil
	}
	// Trust the minimal rendering only if it parses and, once normalized by
	// the same encoder, matches the mutated tree exactly. This tolerates the
	// cosmetic differences we want to keep (blank lines, comment alignment,
	// which the encoder discards on both sides) while catching any case where
	// the text surgery didn't reproduce the intended edit.
	var reparsed yaml.Node
	if err := yaml.Unmarshal(minimal, &reparsed); err != nil {
		return full, nil
	}
	reEnc, err := encodeNode(&reparsed)
	if err != nil {
		return full, nil
	}
	if !bytes.Equal(reEnc, full) {
		return full, nil
	}
	return minimal, nil
}

// encodeNode renders a node through yaml.v3 with the project's 2-space indent.
func encodeNode(n *yaml.Node) ([]byte, error) {
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// renderMinimal applies the recorded edits to the original source. Edits are
// applied bottom-up so line-index shifts from an insertion don't disturb the
// anchors of edits above it. Returns ok=false if any edit can't be applied,
// in which case the caller falls back to a full re-encode.
func (d *Doc) renderMinimal() ([]byte, bool) {
	lines := strings.Split(string(d.src), "\n")
	es := make([]edit, len(d.edits))
	copy(es, d.edits)
	// Descending by anchor line; a stable order is enough since real fixes
	// record a single edit.
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j-1].line < es[j].line; j-- {
			es[j-1], es[j] = es[j], es[j-1]
		}
	}
	for _, e := range es {
		idx := e.line - 1
		if idx < 0 || idx >= len(lines) {
			return nil, false
		}
		switch e.kind {
		case editReplace:
			l := lines[idx]
			start := e.col - 1
			if start < 0 || start > len(l) {
				return nil, false
			}
			end, ok := valueEnd(l, start)
			if !ok {
				return nil, false
			}
			lines[idx] = l[:start] + e.text + l[end:]
		case editInsert:
			ins := strings.Split(e.text, "\n")
			out := make([]string, 0, len(lines)+len(ins))
			out = append(out, lines[:idx+1]...)
			out = append(out, ins...)
			out = append(out, lines[idx+1:]...)
			lines = out
		}
	}
	return []byte(strings.Join(lines, "\n")), true
}

// valueEnd returns the index just past the scalar value that starts at
// 0-based `start`, i.e. before any trailing spaces or "# comment". Quotes are
// respected so a value never ends inside them. Returns ok=false on an
// unterminated quote, so the caller falls back rather than risk a bad edit.
func valueEnd(line string, start int) (int, bool) {
	inSingle, inDouble := false, false
	for i := start; i < len(line); i++ {
		c := line[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == ' ' || c == '\t':
			// Unquoted whitespace ends the value token (any comment follows).
			return i, true
		}
	}
	if inSingle || inDouble {
		return 0, false
	}
	return len(line), true
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
		if indent, ok := mappingChildIndent(svc); ok {
			d.recordInsertAfter(blockEndLine(svc),
				strings.Repeat(" ", indent)+"security_opt:",
				strings.Repeat(" ", indent+2)+"- "+opt)
		} else {
			d.minimalOff = true
		}
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(svc, "security_opt", seq)
		seq.Content = append(seq.Content, scalar(opt))
		return nil
	}
	for _, item := range seq.Content {
		if normalizeOpt(item.Value) == normalizeOpt(opt) {
			return nil // already present
		}
	}
	if prefix, ok := seqItemPrefix(d.src, seq); ok {
		d.recordInsertAfter(blockEndLine(seq), prefix+opt)
	} else {
		d.minimalOff = true
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
	if v := mapGet(svc, key); v != nil {
		d.recordReplace(v, renderRaw(value, v.Style))
		mapSet(svc, key, scalar(value))
		return nil
	}
	if indent, ok := mappingChildIndent(svc); ok {
		d.recordInsertAfter(blockEndLine(svc), strings.Repeat(" ", indent)+key+": "+value)
	} else {
		d.minimalOff = true
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
				d.recordReplace(entry, `"`+rewritten+`"`)
				entry.Value = rewritten
				entry.Style = yaml.DoubleQuotedStyle
				return nil
			}
		case yaml.MappingNode:
			if hp := mapGet(entry, "published"); hp != nil && strings.Trim(hp.Value, `"`) == hostPort {
				// Long-form entries add a host_ip key; leave that to the full
				// re-encode rather than guess the insertion point.
				d.minimalOff = true
				mapSet(entry, "host_ip", scalar("127.0.0.1"))
				return nil
			}
		}
	}
	return fmt.Errorf("port %s not found on service %q", hostPort, service)
}

// recordReplace records an in-place replacement of node's scalar value. If the
// node lacks source position (e.g. it was synthesized), minimal rendering is
// disabled so the caller falls back to the full re-encode.
func (d *Doc) recordReplace(node *yaml.Node, newRaw string) {
	if node == nil || node.Line <= 0 || node.Column <= 0 {
		d.minimalOff = true
		return
	}
	d.edits = append(d.edits, edit{kind: editReplace, line: node.Line, col: node.Column, text: newRaw})
}

// recordInsertAfter records line(s) to insert after a 1-based anchor line.
func (d *Doc) recordInsertAfter(anchor int, lines ...string) {
	if anchor <= 0 {
		d.minimalOff = true
		return
	}
	d.edits = append(d.edits, edit{kind: editInsert, line: anchor, text: strings.Join(lines, "\n")})
}

// renderRaw renders value with the same quoting style as the node it replaces,
// so the minimal text matches what the encoder would emit.
func renderRaw(value string, style yaml.Style) string {
	switch style {
	case yaml.DoubleQuotedStyle:
		return `"` + value + `"`
	case yaml.SingleQuotedStyle:
		return "'" + value + "'"
	default:
		return value
	}
}

// mappingChildIndent returns the leading-space count of a mapping's children,
// derived from its first key's column.
func mappingChildIndent(m *yaml.Node) (int, bool) {
	if m == nil || m.Kind != yaml.MappingNode || len(m.Content) == 0 {
		return 0, false
	}
	if m.Content[0].Column < 1 {
		return 0, false
	}
	return m.Content[0].Column - 1, true
}

// seqItemPrefix returns the leading text (indent + "- ") of a sequence's first
// item, taken verbatim from the source so an appended item lines up with it.
func seqItemPrefix(src []byte, seq *yaml.Node) (string, bool) {
	if seq == nil || len(seq.Content) == 0 {
		return "", false
	}
	first := seq.Content[0]
	lines := strings.Split(string(src), "\n")
	if first.Line-1 < 0 || first.Line-1 >= len(lines) {
		return "", false
	}
	i := strings.Index(lines[first.Line-1], "- ")
	if i < 0 {
		return "", false // flow sequence or unusual layout — fall back
	}
	return lines[first.Line-1][:i+2], true
}

// blockEndLine returns the largest source line among a node and its
// descendants — i.e. the last line the node's content occupies.
func blockEndLine(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	max := n.Line
	for _, c := range n.Content {
		if e := blockEndLine(c); e > max {
			max = e
		}
	}
	return max
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
