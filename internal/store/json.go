//go:build linux

package store

import "encoding/json"

// jsonMarshalCompat and jsonUnmarshalCompat are tiny indirection
// points so the store package's JSON usage can be swapped (e.g.
// to a faster codec) in one place.
var (
	jsonMarshalCompat   = json.Marshal
	jsonUnmarshalCompat = json.Unmarshal
)
