// Package json5 reads JSON5 and rewrites one value in it without disturbing
// anything else in the file.
//
// It exists for the agent domain. OpenClaw documents its config as JSON5 and
// operators comment it heavily, so the config on a real host carries line
// comments, block comments and trailing commas — none of which survive a
// round trip through encoding/json. That is why every agent config-key
// finding was declined a fix: the only available editor would have deleted
// the operator's own notes from a file it was asked to harden.
//
// The scope is deliberately one operation. Set replaces the value at a
// dotted key path that ALREADY EXISTS, and there is no insert, no delete,
// and no re-encode. Every finding this serves fired because the checker read
// a bad value at that path, so the path is present by construction, and
// refusing to create one keeps the hardest part of a JSON5 editor — deciding
// where a new key goes among somebody's comments — out of the code entirely.
//
// # Why there is no fallback
//
// internal/compose/edit.go does minimal text surgery too, and when it cannot
// prove the result correct it falls back to re-encoding the whole document
// through yaml.v3. That is safe there because yaml.v3 preserves comments.
//
// There is no such fallback here. Re-encoding JSON5 through encoding/json is
// exactly the data loss this package exists to avoid, so a rendering that
// cannot be proven correct is an error, never a quieter kind of success.
// Bytes returns that error and the fix is not offered.
package json5

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Doc is a JSON5 document with a recorded set of pending value replacements.
// Mutations are held in memory; callers render with Bytes and decide whether
// to write. Nothing here touches disk, which is what lets a fix's Transform
// stay pure and a preview stay a diff.
type Doc struct {
	src   []byte
	spans map[string]span // dotted path -> byte extent of its value
	amb   map[string]bool // paths a literal dot in a key made ambiguous
	tree  map[string]any  // decoded form, for verification
	edits map[string]any  // dotted path -> replacement value
	order []string        // edit paths, in the order they were set
}

// Load parses src, recording where every addressable value sits in the
// original bytes.
func Load(src []byte) (*Doc, error) {
	tree, err := Decode(src)
	if err != nil {
		return nil, err
	}
	spans, amb, err := locate(src)
	if err != nil {
		return nil, fmt.Errorf("locating values: %w", err)
	}
	return &Doc{
		src:   append([]byte(nil), src...),
		spans: spans,
		amb:   amb,
		tree:  tree,
		edits: map[string]any{},
	}, nil
}

// Has reports whether a dotted path names a value this document can rewrite.
func (d *Doc) Has(path string) bool {
	if d.amb[path] {
		return false
	}
	_, ok := d.spans[path]
	return ok
}

// Set records that the value at a dotted path becomes v, which must be a
// value encoding/json can marshal — the callers pass strings and bools.
//
// An absent path is an error rather than an insertion. See the package
// comment: every finding served here fired on a value that was read, so a
// path that is not there means the file changed under the fix or the finding
// was built wrong, and both are worth reporting rather than papering over.
func (d *Doc) Set(path string, v any) error {
	if d.amb[path] {
		return fmt.Errorf("key path %q is ambiguous: a key in this document contains a literal '.'", path)
	}
	if _, ok := d.spans[path]; !ok {
		return fmt.Errorf("key path %q is not present in this config", path)
	}
	if _, err := json.Marshal(v); err != nil {
		return fmt.Errorf("value for %q cannot be encoded: %w", path, err)
	}
	if _, seen := d.edits[path]; !seen {
		d.order = append(d.order, path)
	}
	d.edits[path] = v
	return nil
}

// Bytes renders the document with the recorded replacements applied.
//
// The rendering is verified before it is returned: the result is re-parsed
// and compared against the original tree with exactly the recorded edits
// applied to it. A mismatch means the text surgery changed something it was
// not asked to, and that is an error — never a fallback, because the only
// fallback available would discard the comments this package exists to keep.
func (d *Doc) Bytes() ([]byte, error) {
	if len(d.order) == 0 {
		return append([]byte(nil), d.src...), nil
	}

	type patch struct {
		span
		lit []byte
	}
	patches := make([]patch, 0, len(d.order))
	for _, p := range d.order {
		lit, err := json.Marshal(d.edits[p])
		if err != nil {
			return nil, fmt.Errorf("encoding value for %q: %w", p, err)
		}
		patches = append(patches, patch{span: d.spans[p], lit: lit})
	}
	// Apply back to front so an earlier patch's offsets stay valid.
	sort.Slice(patches, func(i, j int) bool { return patches[i].start > patches[j].start })

	out := append([]byte(nil), d.src...)
	for i, p := range patches {
		if p.start < 0 || p.end > len(out) || p.start > p.end {
			return nil, fmt.Errorf("recorded extent for edit %d is out of range", i)
		}
		merged := make([]byte, 0, len(out)-(p.end-p.start)+len(p.lit))
		merged = append(merged, out[:p.start]...)
		merged = append(merged, p.lit...)
		merged = append(merged, out[p.end:]...)
		out = merged
	}

	want := cloneTree(d.tree)
	for _, p := range d.order {
		if err := assign(want, p, d.edits[p]); err != nil {
			return nil, err
		}
	}
	got, err := Decode(out)
	if err != nil {
		return nil, fmt.Errorf("the edited config no longer parses, so it was not written: %w", err)
	}
	if !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("editing %s changed more than the keys it was asked to; refusing to write",
			strings.Join(d.order, ", "))
	}
	return out, nil
}

// assign writes v at a dotted path in a decoded tree, for verification only.
// The path is known to exist, so a missing node is a bug rather than input.
func assign(m map[string]any, dotted string, v any) error {
	parts := strings.Split(dotted, ".")
	cur := m
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur[part].(map[string]any)
		if !ok {
			return fmt.Errorf("key path %q does not resolve to an object at %q", dotted, part)
		}
		cur = next
	}
	// Through the same round trip the comparison value takes, so a Go string
	// and a decoded JSON string compare equal.
	var normalized any
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &normalized); err != nil {
		return err
	}
	cur[parts[len(parts)-1]] = normalized
	return nil
}

// clone deep-copies a decoded tree so verification never mutates the
// document's own record of what it parsed.
func clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = clone(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = clone(val)
		}
		return out
	default:
		return v
	}
}

// cloneTree is clone with the map type the callers need.
func cloneTree(m map[string]any) map[string]any {
	c, _ := clone(m).(map[string]any)
	return c
}
