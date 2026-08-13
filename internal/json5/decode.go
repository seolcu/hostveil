package json5

import (
	"encoding/json"
	"fmt"
)

// Decode parses a JSON5 document into a generic tree.
//
// Strict JSON is tried first and the strip pass only runs when that fails,
// so an ordinary JSON config never pays for the tolerance. The tolerance is
// not a nicety: OpenClaw documents its config as JSON5 and users comment it
// heavily, so without it a commented config would be unparseable, every
// OpenClaw host would report Degraded, and a flag that means "partial
// coverage" everywhere means nothing anywhere.
func Decode(b []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err == nil {
		return m, nil
	}
	if err := json.Unmarshal(Strip(b), &m); err != nil {
		return nil, fmt.Errorf("parsing JSON5 config: %w", err)
	}
	return m, nil
}

// Strip removes line comments, block comments, and trailing commas, leaving
// something encoding/json will accept.
//
// It tracks string literals so a "//" inside a value — a URL, most often — is
// never mistaken for a comment. Comments are replaced by nothing rather than
// by spaces except for the newline that ends a line comment, which is kept so
// that a trailing comma before it is still recognised.
func Strip(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(b) {
			if b[i+1] == '/' {
				for i < len(b) && b[i] != '\n' {
					i++
				}
				if i < len(b) {
					out = append(out, '\n')
				}
				continue
			}
			if b[i+1] == '*' {
				i += 2
				for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
					i++
				}
				i++ // sit on the closing '/', the loop's i++ steps past it
				continue
			}
		}
		out = append(out, c)
	}
	return stripTrailingCommas(out)
}

// stripTrailingCommas removes any comma whose next non-space character closes
// an object or array. It is string-aware for the same reason Strip is.
func stripTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue // drop the comma, keep the whitespace
			}
		}
		out = append(out, c)
	}
	return out
}
