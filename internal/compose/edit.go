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
	editDelete                  // delete lines line..end inclusive
)

type edit struct {
	kind editKind
	line int    // 1-based anchor line in the original source
	col  int    // 1-based start column of the value (editReplace only)
	text string // replacement token (editReplace) or lines to insert (editInsert)
	end  int    // 1-based last line to delete (editDelete only)
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
	// The minimal path below is already checked against full — parsed,
	// re-encoded, and compared byte for byte — before it is trusted. full
	// itself never was: FuzzEdit found a source (a flow mapping keyed by
	// another mapping) that yaml.v3 parses but cannot faithfully write back,
	// so a fix landing on the no-edits-recorded or minimalOff path returned
	// bytes no parser could read, with the caller none the wiser until the
	// service that reads the file next fails to start. A fix is only ever
	// built against a service and key the checker already read, so this
	// should never actually fire outside the fuzz corpus — but a write this
	// package cannot prove readable is exactly the case Auto fixes exist to
	// never produce.
	if err := verifyReloadable(full); err != nil {
		return nil, fmt.Errorf("re-encoded document does not parse back as YAML: %w", err)
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

// verifyReloadable reports whether b parses as YAML, without caring what it
// parses into — Bytes' callers already know the shape they expect and will
// fail their own way if it's wrong. This only guards against handing back
// something no parser can read at all.
func verifyReloadable(b []byte) error {
	var n yaml.Node
	return yaml.Unmarshal(b, &n)
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
		case editDelete:
			last := e.end - 1
			if last < idx || last >= len(lines) {
				return nil, false
			}
			lines = append(lines[:idx:idx], lines[last+1:]...)
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
	return d.addSeqItem(service, "security_opt", opt)
}

// addSeqItem appends item to service.<key>, creating the list if needed. It
// is a no-op if an equivalent item is already present.
func (d *Doc) addSeqItem(service, key, opt string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	seq := mapGet(svc, key)
	if seq == nil {
		if indent, ok := mappingChildIndent(svc); ok {
			d.recordInsertAfter(blockEndLine(svc),
				strings.Repeat(" ", indent)+key+":",
				strings.Repeat(" ", indent+2)+"- "+opt)
		} else {
			d.minimalOff = true
		}
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mapSet(svc, key, seq)
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
	return d.setTyped(service, key, value, "!!str")
}

// SetBool sets service.<key> to a YAML boolean. SetScalar would tag it as a
// string, which the encoder then quotes, and compose rejects "true" where it
// wants true.
func (d *Doc) SetBool(service, key string, value bool) error {
	v := "false"
	if value {
		v = "true"
	}
	return d.setTyped(service, key, v, "!!bool")
}

func (d *Doc) setTyped(service, key, value, tag string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	if v := mapGet(svc, key); v != nil {
		style := v.Style
		if tag != "!!str" {
			style = 0 // a quoted boolean is a string
		}
		d.recordReplace(v, renderRaw(value, style))
		mapSet(svc, key, node)
		return nil
	}
	if indent, ok := mappingChildIndent(svc); ok {
		d.recordInsertAfter(blockEndLine(svc), strings.Repeat(" ", indent)+key+": "+value)
	} else {
		d.minimalOff = true
	}
	mapSet(svc, key, node)
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

// RemoveKey deletes service.<key> and everything under it. It is the shape
// of every removal-type fix — privileged, network_mode, pid, ipc,
// userns_mode — where the remediation is taking out a line the author put
// there. A key that is not present is an error rather than a no-op, because
// the fix was built from a finding that said it was.
func (d *Doc) RemoveKey(service, key string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	for i := 0; i+1 < len(svc.Content); i += 2 {
		if svc.Content[i].Value != key {
			continue
		}
		d.recordDelete(svc.Content[i].Line, blockEndLine(svc.Content[i+1]))
		svc.Content = append(svc.Content[:i:i], svc.Content[i+2:]...)
		return nil
	}
	return fmt.Errorf("service %q has no %s", service, key)
}

// RemoveSeqItem deletes the first item of service.<key> for which match
// returns true. Removing the last item removes the key too, because an empty
// block sequence renders as a null, which is not what the author wrote and
// not what the encoder would write either.
func (d *Doc) RemoveSeqItem(service, key string, match func(*yaml.Node) bool) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	seq := mapGet(svc, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("service %q has no %s list", service, key)
	}
	for i, item := range seq.Content {
		if !match(item) {
			continue
		}
		if len(seq.Content) == 1 {
			return d.RemoveKey(service, key)
		}
		d.recordDelete(item.Line, blockEndLine(item))
		seq.Content = append(seq.Content[:i:i], seq.Content[i+1:]...)
		return nil
	}
	return fmt.Errorf("no matching %s entry on service %q", key, service)
}

// RemoveSecurityOpt deletes opt from a service's security_opt list,
// comparing the way the checker does: case-insensitively, spaces ignored.
func (d *Doc) RemoveSecurityOpt(service, opt string) error {
	return d.RemoveSeqItem(service, "security_opt", func(n *yaml.Node) bool {
		return n.Kind == yaml.ScalarNode && strings.EqualFold(normalizeOpt(n.Value), normalizeOpt(opt))
	})
}

// RemoveCapAdd deletes capability from a service's cap_add list. The CAP_
// prefix is optional in compose, so it is optional here.
func (d *Doc) RemoveCapAdd(service, capability string) error {
	want := capName(capability)
	return d.RemoveSeqItem(service, "cap_add", func(n *yaml.Node) bool {
		return n.Kind == yaml.ScalarNode && capName(n.Value) == want
	})
}

func capName(s string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "CAP_")
}

// RemoveVolume deletes the volume whose host source is source, in either the
// short ("src:dst[:mode]") or the long (`source:`) form.
func (d *Doc) RemoveVolume(service, source string) error {
	want := strings.TrimSuffix(source, "/")
	return d.RemoveSeqItem(service, "volumes", func(n *yaml.Node) bool {
		return volumeSource(n) == want
	})
}

// SetVolumeReadOnly makes the volume whose host source is source read-only:
// `:ro` on the short form (replacing an explicit `rw`), `read_only: true` on
// the long form.
func (d *Doc) SetVolumeReadOnly(service, source string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	vols := mapGet(svc, "volumes")
	if vols == nil {
		return fmt.Errorf("service %q has no volumes", service)
	}
	want := strings.TrimSuffix(source, "/")
	for _, entry := range vols.Content {
		if volumeSource(entry) != want {
			continue
		}
		switch entry.Kind {
		case yaml.ScalarNode:
			rewritten := shortVolumeReadOnly(entry.Value)
			d.recordReplace(entry, renderRaw(rewritten, entry.Style))
			entry.Value = rewritten
			return nil
		case yaml.MappingNode:
			// Same reasoning as BindPortLoopback's long form: the insertion
			// point inside a flow-or-block mapping item is not worth guessing.
			d.minimalOff = true
			mapSet(entry, "read_only", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
			return nil
		}
	}
	return fmt.Errorf("no volume from %s on service %q", source, service)
}

// volumeSource is a volume entry's host side, trailing slash trimmed, or ""
// for an entry it cannot read.
func volumeSource(n *yaml.Node) string {
	switch n.Kind {
	case yaml.ScalarNode:
		src, _, _ := strings.Cut(n.Value, ":")
		return strings.TrimSuffix(src, "/")
	case yaml.MappingNode:
		if v := mapGet(n, "source"); v != nil {
			return strings.TrimSuffix(v.Value, "/")
		}
	}
	return ""
}

// shortVolumeReadOnly rewrites "src:dst" or "src:dst:opts" so its options
// include ro and not rw.
func shortVolumeReadOnly(v string) string {
	parts := strings.SplitN(v, ":", 3)
	if len(parts) < 3 {
		return v + ":ro"
	}
	var opts []string
	for _, o := range strings.Split(parts[2], ",") {
		if o != "rw" && o != "ro" && o != "" {
			opts = append(opts, o)
		}
	}
	opts = append([]string{"ro"}, opts...)
	return parts[0] + ":" + parts[1] + ":" + strings.Join(opts, ",")
}

// SetReadOnlyRootfs sets read_only: true and mounts a tmpfs at each of
// tmpfs, the two halves of one change: a read-only root with nowhere to
// write /tmp is the version that takes most images down.
//
// When neither key exists both are inserted as one edit, so the minimal
// rendering keeps their order; anything else falls through to the
// individual mutations and, if their text edits cannot be proven, the full
// re-encode.
func (d *Doc) SetReadOnlyRootfs(service string, tmpfs []string) error {
	svc := d.service(service)
	if svc == nil {
		return fmt.Errorf("service %q not found", service)
	}
	if mapGet(svc, "read_only") == nil && mapGet(svc, "tmpfs") == nil && len(tmpfs) > 0 {
		if indent, ok := mappingChildIndent(svc); ok {
			pad := strings.Repeat(" ", indent)
			lines := []string{pad + "read_only: true", pad + "tmpfs:"}
			for _, p := range tmpfs {
				lines = append(lines, pad+"  - "+p)
			}
			d.recordInsertAfter(blockEndLine(svc), lines...)
		} else {
			d.minimalOff = true
		}
		mapSet(svc, "read_only", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, p := range tmpfs {
			seq.Content = append(seq.Content, scalar(p))
		}
		mapSet(svc, "tmpfs", seq)
		return nil
	}
	if err := d.SetBool(service, "read_only", true); err != nil {
		return err
	}
	for _, p := range tmpfs {
		if err := d.addSeqItem(service, "tmpfs", p); err != nil {
			return err
		}
	}
	return nil
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

// recordDelete records the removal of source lines line..end. A node with no
// source position cannot be located, so minimal rendering is disabled.
func (d *Doc) recordDelete(line, end int) {
	if line <= 0 || end < line {
		d.minimalOff = true
		return
	}
	d.edits = append(d.edits, edit{kind: editDelete, line: line, end: end})
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
