package model

// This file holds the two helpers every enum table in this package is built
// from. They exist to make one rule mechanical: a row is found by its enum
// value, never by its position in the slice.
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
