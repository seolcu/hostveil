package model

import (
	"encoding/json"
	"fmt"
)

// This file holds the helpers every enum table in this package is built
// from. The first two exist to make one rule mechanical: a row is found by
// its enum value, never by its position in the slice.
//
// The distinction is not academic. Source's table starts at SourceCompose
// (1) because SourceUnset owns 0, so its rows sit one off from their values;
// Severity's starts at SeverityCritical (0), so its rows do not. Indexing by
// position works for one and is an off-by-one for the other, and the two
// tables sit in the same package looking identical. Since these values are
// serialized as bare integers into on-disk scan snapshots, that off-by-one
// would not show up in any test — every test round-trips through the same
// table — and would surface only as a previous scan whose findings all
// changed domain, which reads to a user as "everything on this host is new".

// indexBy builds a lookup from an enum table, keyed by the value each row
// describes.
func indexBy[T any, K comparable](defs []T, key func(T) K) map[K]T {
	m := make(map[K]T, len(defs))
	for _, d := range defs {
		m[key(d)] = d
	}
	return m
}

// columnOf projects one column out of an enum table, preserving row order.
func columnOf[T any, C any](defs []T, col func(T) C) []C {
	out := make([]C, len(defs))
	for i, d := range defs {
		out[i] = col(d)
	}
	return out
}

// The rest of this file is the other direction: how an enum crosses the wire
// and the disk.
//
// These values used to be written out as bare integers, which made the
// numbering a compatibility surface. Every consumer of `scan --json` had to
// keep its own copy of the ordering, the dashboard had to be handed generated
// lookup tables to read its own API, and renumbering an enum silently
// reinterpreted every scan snapshot already on disk — a 1 that meant High
// reading back as whatever now sits at 1, with no error anywhere and the only
// symptom a previous scan whose findings had all changed meaning.
//
// model.FixVerification solved this for itself by marshalling its name, and
// internal/ui/web/modeljs.go named the migration: "that is the better fix,
// and it is open to any enum that is not already on disk as an integer".
// These are, so the move has to carry the old form with it — unmarshalling
// accepts a name *or* an integer, and the integer path is what lets a
// snapshot written before this release still be read.
//
// Note for anything added later: encoding/json uses Marshaler for values and
// TextMarshaler for map keys, and only Marshaler is implemented here. No
// serialized type in this package is keyed by an enum today (Report.Domains
// is a slice precisely because it is a wire format), and a future one would
// need MarshalText as well.

// nameIndex builds the reverse of an enum table: name to value.
func nameIndex[T any, V comparable](defs []T, val func(T) V, name func(T) string) map[string]V {
	m := make(map[string]V, len(defs))
	for _, d := range defs {
		m[name(d)] = val(d)
	}
	return m
}

// marshalEnum writes an enum as its name.
func marshalEnum(name string) ([]byte, error) { return json.Marshal(name) }

// unmarshalEnum reads an enum written either as its name or as the bare
// integer this package used to emit.
//
// An unrecognised value is an error rather than a fallback. The two answers
// are not interchangeable: quietly resolving to a zero value would turn a
// snapshot hostveil cannot read into one it reads wrongly, which is the same
// trade the scanner refuses everywhere else. Callers that survive a bad
// snapshot — ScoreHistory skips one that will not unmarshal — already handle
// the error, and they can only do that if there is one.
func unmarshalEnum[V ~int](data []byte, kind string, byName map[string]V, valid func(V) bool) (V, error) {
	var zero V
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return zero, err
		}
		v, ok := byName[s]
		if !ok {
			return zero, fmt.Errorf("unknown %s %q", kind, s)
		}
		return v, nil
	}
	var n int
	if err := json.Unmarshal(data, &n); err != nil {
		return zero, fmt.Errorf("%s must be a name or an integer: %w", kind, err)
	}
	if v := V(n); valid(v) {
		return v, nil
	}
	return zero, fmt.Errorf("unknown %s %d", kind, n)
}
