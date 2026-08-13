package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/seolcu/hostveil/internal/json5"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/secretkey"
)

// decodeConfig parses a runtime config into a generic tree.
//
// The JSON5 half lives in internal/json5 because the fix that edits these
// files needs the same parser. Two copies of a tolerant parser is two
// answers to "is this key set", and the checker and the fix disagreeing
// about that is how a fix reports success on a file it never understood.
func decodeConfig(b []byte, format ConfigFormat) (map[string]any, error) {
	if format == FormatYAML {
		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("parsing YAML config: %w", err)
		}
		return m, nil
	}
	return json5.Decode(b)
}

// remediation decides how much human judgment a danger finding needs, and
// records the values that would settle it.
//
// The checker answers "how much judgment", never "does a fix exist" — that is
// the registry's half, and Engine.classify resolves the two by caution. What
// this decides is read straight off the rules that tripped:
//
//   - a key with no safe value in the table keeps the finding Manual. Nothing
//     here knows what turns OpenClaw's sandbox on, and writing a guessed enum
//     into somebody's config is worse than leaving the finding to them;
//   - a key with two safe values makes it Review, because deny and ask are a
//     choice about how the operator wants to work, not a sequence;
//   - otherwise Auto: one mechanical value, in a file edit, that cannot cut
//     anyone off from the host.
//
// The values travel as evidence rather than being re-derived by the fix,
// because internal/fix cannot import this package and a second copy of this
// table is a second answer to what "safe" means. Each is a JSON literal, so
// `false` and `"deny"` stay distinguishable through the string.
//
// A runtime whose config is not JSON5 gets no values at all. Hermes has no
// danger rules today; if it gains some, its bind and auth can come from the
// config, an env file, a systemd unit or a docker flag, and editing the file
// could silently change nothing. That decline is recorded in fix.Default.
func remediation(rt Runtime, rules []DangerRule) (model.RemediationKind, string, string) {
	if rt.Format != FormatJSON5 {
		return model.RemediationManual, "", ""
	}
	choice := false
	for _, r := range rules {
		if len(r.Good) == 0 {
			return model.RemediationManual, "", ""
		}
		if len(r.Good) > 1 {
			choice = true
		}
	}

	primary := make([]string, 0, len(rules))
	alt := make([]string, 0, len(rules))
	for _, r := range rules {
		primary = append(primary, assignment(r.Key, r.Good[0]))
		if len(r.Good) > 1 {
			alt = append(alt, assignment(r.Key, r.Good[1]))
		} else {
			alt = append(alt, assignment(r.Key, r.Good[0]))
		}
	}
	if !choice {
		return model.RemediationAuto, strings.Join(primary, model.EvidenceSeparator), ""
	}
	return model.RemediationReview,
		strings.Join(primary, model.EvidenceSeparator),
		strings.Join(alt, model.EvidenceSeparator)
}

// assignment renders one key=value pair for the "set" evidence, with the
// value as a JSON literal so the fix knows whether to write false or "false".
func assignment(key string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Every value in the table is a string or a bool, so this is
		// unreachable; rendering it visibly is better than a pair the fix
		// would silently misread.
		return key + "=?"
	}
	return key + "=" + string(b)
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

// maxAgentFileBytes bounds every read under a user's home. The largest real
// config is a few hundred kilobytes of commented JSON5; a megabyte of headroom
// keeps any legitimate file readable while a symlink at /dev/zero stays a
// bounded error instead of an allocation that never ends.
const maxAgentFileBytes = 1 << 20

// loadEnvFile parses a KEY=value file. safeKeys names the variables whose
// values the caller needs; every other variable is reported by presence only.
func loadEnvFile(path string, safeKeys []string) (envFile, error) {
	b, err := platform.ReadFileNoFollow(path, maxAgentFileBytes)
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
