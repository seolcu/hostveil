package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seolcu/hostveil/internal/secretkey"
)

// decodeConfig parses a runtime config into a generic tree.
//
// JSON5 is tried as strict JSON first and only re-parsed after stripping
// comments and trailing commas if that fails. The strip pass is not a nicety:
// OpenClaw documents its config as JSON5 and users comment it heavily, so
// without it a commented config would be unparseable, every OpenClaw host
// would report Degraded, and a flag that means "partial coverage" everywhere
// means nothing anywhere.
func decodeConfig(b []byte, format ConfigFormat) (map[string]any, error) {
	if format == FormatYAML {
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("parsing YAML config: %w", err)
		}
		return m, nil
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err == nil {
		return m, nil
	}
	if err := json.Unmarshal(stripJSON5(b), &m); err != nil {
		return nil, fmt.Errorf("parsing JSON5 config: %w", err)
	}
	return m, nil
}

// stripJSON5 removes line comments, block comments, and trailing commas,
// leaving something encoding/json will accept.
//
// It tracks string literals so a "//" inside a value — a URL, most often — is
// never mistaken for a comment. Comments are replaced by nothing rather than
// by spaces except for the newline that ends a line comment, which is kept so
// that a trailing comma before it is still recognised.
func stripJSON5(b []byte) []byte {
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
// an object or array. It is string-aware for the same reason stripJSON5 is.
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

// lookup walks a dotted key path ("gateway.auth.mode") through a decoded
// config tree.
func lookup(m map[string]any, dotted string) (any, bool) {
	if m == nil || dotted == "" {
		return nil, false
	}
	var cur any = m
	for _, part := range strings.Split(dotted, ".") {
		node, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok := node[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// scalar renders a config value as the string the DangerRule table compares
// against, so one table covers string enums and booleans alike.
func scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// lookupString resolves a dotted config key to a string, "" when absent.
func lookupString(m map[string]any, dotted string) string {
	v, ok := lookup(m, dotted)
	if !ok {
		return ""
	}
	return scalar(v)
}

// envFile is what a runtime's KEY=value file tells us. Values holds only the
// keys the caller declared safe to read; Present records every key by name.
//
// The split is the whole point. A credential must be able to influence a
// finding — "your API key file is world-readable" needs to know a key is in
// there — without the value ever reaching a Finding, because evidence is
// rendered by every UI and persisted to disk. Presence is enough to make the
// claim; the value would only ever be a liability.
type envFile struct {
	Values  map[string]string
	Present map[string]bool
	// SecretKeys are the credential-named keys carrying a literal value,
	// sorted. Names only, never values.
	SecretKeys []string
}

// loadEnvFile parses a KEY=value file. safeKeys names the variables whose
// values the caller needs; every other variable is reported by presence only.
func loadEnvFile(path string, safeKeys []string) (envFile, error) {
	b, err := os.ReadFile(path) //nolint:gosec // path comes from the runtime registry
	if err != nil {
		return envFile{}, err
	}
	safe := make(map[string]bool, len(safeKeys))
	for _, k := range safeKeys {
		safe[k] = true
	}

	ef := envFile{Values: map[string]string{}, Present: map[string]bool{}}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)

		ef.Present[k] = true
		if safe[k] {
			ef.Values[k] = v
		}
		if secretkey.Matches(k) && secretkey.LooksLiteral(v) {
			ef.SecretKeys = append(ef.SecretKeys, k)
		}
	}
	sort.Strings(ef.SecretKeys) // stable evidence across runs
	return ef, nil
}
