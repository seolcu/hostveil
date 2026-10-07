package fix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// setJSONKey sets a top-level key of a JSON object to raw, a JSON value,
// changing nothing else in the file.
//
// daemon.json is plain JSON, so re-encoding it through encoding/json would be
// correct. It would also sort every key and reflow the file, turning a
// one-line change into a diff of the whole document — which is the thing the
// preview exists to keep readable. So the value's bytes are located with the
// decoder's own offsets and replaced, or a new member is inserted before the
// closing brace, and the result is trusted only if it parses to exactly the
// original object with that one key set. Anything else is an error rather
// than a guess, the same contract internal/json5 keeps for the agent configs.
func setJSONKey(in []byte, key, raw string) ([]byte, error) {
	if !json.Valid([]byte(raw)) {
		return nil, fmt.Errorf("value for %q is not JSON: %s", key, raw)
	}
	if len(bytes.TrimSpace(in)) == 0 {
		return []byte("{\n  " + quoteKey(key) + ": " + raw + "\n}\n"), nil
	}
	var before map[string]any
	if err := json.Unmarshal(in, &before); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}

	var out []byte
	if start, end, ok := topLevelValue(in, key); ok {
		out = append(append(append([]byte{}, in[:start]...), raw...), in[end:]...)
	} else {
		var err error
		if out, err = insertMember(in, key, raw); err != nil {
			return nil, err
		}
	}

	var after, want map[string]any
	if err := json.Unmarshal(out, &after); err != nil {
		return nil, fmt.Errorf("setting %q produced invalid JSON: %w", key, err)
	}
	if err := json.Unmarshal(in, &want); err != nil {
		return nil, err
	}
	var v any
	_ = json.Unmarshal([]byte(raw), &v)
	want[key] = v
	if !reflect.DeepEqual(after, want) {
		return nil, fmt.Errorf("setting %q changed more of the file than that key; not writing it", key)
	}
	return out, nil
}

// topLevelValue finds the byte span of key's value in a top-level object.
func topLevelValue(in []byte, key string) (start, end int, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(in))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, 0, false
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return 0, 0, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return 0, 0, false
		}
		if k, _ := t.(string); k == key {
			end := int(dec.InputOffset())
			return end - len(raw), end, true
		}
	}
	return 0, 0, false
}

// insertMember adds "key": raw as the last member, indented like the first
// member if there is one.
func insertMember(in []byte, key, raw string) ([]byte, error) {
	closing := bytes.LastIndexByte(in, '}')
	if closing < 0 {
		return nil, fmt.Errorf("no closing brace")
	}
	body := bytes.TrimRight(in[:closing], " \t\r\n")
	indent := memberIndent(in)
	member := indent + quoteKey(key) + ": " + raw
	var b bytes.Buffer
	b.Write(body)
	if len(body) > 0 && body[len(body)-1] != '{' {
		b.WriteByte(',')
	}
	b.WriteString("\n" + member + "\n")
	b.Write(in[closing:])
	return b.Bytes(), nil
}

// memberIndent is the leading whitespace of the first line that starts a
// member, or two spaces.
func memberIndent(in []byte) string {
	for _, line := range strings.Split(string(in), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, `"`) {
			return line[:len(line)-len(trimmed)]
		}
	}
	return "  "
}

func quoteKey(k string) string {
	b, _ := json.Marshal(k)
	return string(b)
}
