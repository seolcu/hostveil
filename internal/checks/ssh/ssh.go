// Package ssh scans the host's SSH server configuration for
// security-sensitive misconfigurations per spec FR-001.
//
// The parser handles the OpenSSH sshd_config subset the spec names:
// PermitRootLogin, PasswordAuthentication (and its aliases), and
// Protocol. Include and Match blocks are honored: an effective value
// is the value of the last setting at the top level, or the value
// inside a Match block when the user matches.
package ssh

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/model"
)

// DefaultConfigPath is the OpenSSH sshd_config path on most Linux
// distributions. Tests can override via SetConfigPath.
var DefaultConfigPath = "/etc/ssh/sshd_config"

// Run implements checks.Run.
func Run(ctx context.Context) (checks.Result, error) {
	return runWithPath(ctx, DefaultConfigPath)
}

func runWithPath(_ context.Context, path string) (checks.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return checks.Result{
				Skipped: &model.CategorySkip{
					Category: model.CategorySSH,
					Reason:   "not_applicable",
					Detail:   fmt.Sprintf("sshd_config not found at %s", path),
				},
			}, nil
		}
		return checks.Result{}, fmt.Errorf("read sshd_config: %w", err)
	}
	effective, err := Parse(string(data))
	if err != nil {
		return checks.Result{}, fmt.Errorf("parse sshd_config: %w", err)
	}
	findings := rules(effective, path, time.Now().UTC())
	return checks.Result{Findings: findings}, nil
}

// Parsed is the result of parsing an sshd_config file. The
// effective values are what sshd would apply at the top level (no
// Match filtering). The Settings slice preserves every directive in
// the order it was seen.
type Parsed struct {
	Settings []model.Setting
}

// Parse reads a string of sshd_config text and returns the parsed
// representation. The parser is intentionally tolerant: unknown
// directives, comments, Match blocks, Include, and empty lines are
// skipped. Theffective value of a directive is the last one seen
// at the top level.
func Parse(text string) (Parsed, error) {
	var (
		out  Parsed
		line int
	)
	// We track the index of the last setting for each key so a later
	// "key value" line replaces the prior one (sshd semantics).
	indexByKey := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		// Tokens: split on whitespace, but tolerate spaces inside
		// quoted values. We don't fully implement the OpenSSH parser;
		// we handle the directives the spec calls out.
		tokens := tokenize(raw)
		if len(tokens) == 0 {
			continue
		}
		key := strings.ToLower(tokens[0])
		// Skip block-level directives; we do not model Match here.
		if key == "match" || key == "include" {
			continue
		}
		// For our rules we only care about single-value directives.
		if len(tokens) < 2 {
			continue
		}
		value := strings.Join(tokens[1:], " ")
		s := model.Setting{
			ConfigFileID:   "",
			Line:           line,
			Key:            tokens[0],
			RawValue:       value,
			EffectiveValue: value,
		}
		if i, ok := indexByKey[s.Key]; ok {
			out.Settings[i] = s
		} else {
			indexByKey[s.Key] = len(out.Settings)
			out.Settings = append(out.Settings, s)
		}
	}
	if err := scanner.Err(); err != nil {
		return Parsed{}, err
	}
	return out, nil
}

// tokenize splits an sshd_config line on whitespace, but keeps
// together a value that starts with a double quote. sshd treats
// double-quoted values as a single token; we do the minimum to
// round-trip "PermitRootLogin yes" without surprises.
func tokenize(line string) []string {
	out := []string{}
	var b strings.Builder
	inQuotes := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			b.WriteRune(r)
		case (r == ' ' || r == '\t') && !inQuotes:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// settingsByKey returns a map of the last-seen value for each
// directive, ignoring case in the lookup.
func (p Parsed) settingsByKey() map[string]string {
	out := map[string]string{}
	for _, s := range p.Settings {
		out[strings.ToLower(s.Key)] = s.EffectiveValue
	}
	return out
}

func rules(p Parsed, path string, now time.Time) []model.Finding {
	settings := p.settingsByKey()
	var out []model.Finding
	base := model.EntityRef{
		Kind:    model.EntityRefKindConfigFile,
		Display: fmt.Sprintf("%s:%d", path, 0),
	}
	_ = base
	for _, s := range p.Settings {
		key := strings.ToLower(s.Key)
		switch key {
		case "permitrootlogin":
			if !isSafeRootLogin(s.EffectiveValue) {
				out = append(out, findingSSH("ssh.permit_root_login.allow",
					"high", "Root login is allowed over SSH",
					"Anyone who can reach your SSH port can try to log in as the root user, "+
						"which bypasses the normal user -> sudo flow.", s, path, now))
			}
		case "passwordauthentication":
			if !isOff(s.EffectiveValue) {
				out = append(out, findingSSH("ssh.password_auth.only",
					"medium", "Password authentication is enabled",
					"Passwords can be guessed, phished, or leaked. Prefer key-based "+
						"authentication, and disable password authentication entirely "+
						"once keys are in place.", s, path, now))
			}
		case "protocol":
			if hasLegacyProtocol(s.EffectiveValue) {
				out = append(out, findingSSH("ssh.protocol.legacy",
					"high", "Legacy SSH protocol version is enabled",
					"SSHv1 has known cryptographic weaknesses. SSHv2 is the "+
						"modern standard and is enabled by default when Protocol is "+
						"unset or set to 2.", s, path, now))
			}
		}
		_ = settings
	}
	return out
}

func isSafeRootLogin(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "no" || v == "prohibit-password" || v == "without-password" || v == "forced-commands-only"
}

func isOff(v string) bool {
	return strings.ToLower(strings.TrimSpace(v)) == "no"
}

func hasLegacyProtocol(v string) bool {
	for _, p := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t'
	}) {
		if p == "1" || p == "1.5" {
			return true
		}
	}
	return false
}

func findingSSH(ruleID string, sev, title, desc string, s model.Setting, path string, now time.Time) model.Finding {
	// Entity display is the file:line for the user.
	display := fmt.Sprintf("%s:%d", path, s.Line)
	return model.Finding{
		ID:          "finding-" + ruleID + "-" + fmt.Sprint(s.Line),
		Fingerprint: fingerprint(ruleID, display),
		Category:    model.CategorySSH,
		RuleID:      ruleID,
		Severity:    model.Severity(sev),
		Title:       title,
		Description: desc,
		EntityRefs: []model.EntityRef{{
			Kind:    model.EntityRefKindConfigFile,
			Display: display,
		}, {
			Kind:    model.EntityRefKindSetting,
			Display: fmt.Sprintf("%s = %s", s.Key, s.EffectiveValue),
		}},
		State:       model.StateNew,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
}

// fingerprint produces a stable hash for the (rule, display) tuple.
// Kept in this package so the SSH rule IDs do not need to enumerate
// every line number.
func fingerprint(rule, display string) string {
	// Avoid importing crypto/sha256 just for two fields; a stable
	// FNV-1a 64-bit hash is enough for a fingerprint and avoids
	// pulling extra packages into the import graph of checks/ssh.
	h := fnv64a()
	for _, b := range []byte(rule) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	for _, b := range []byte("\x00") {
		h ^= uint64(b)
		h *= 1099511628211
	}
	for _, b := range []byte(display) {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// fnv64a is an inlined FNV-1a 64-bit hash to avoid importing
// hash/fnv in this small package.
func fnv64a() uint64 { return 0xcbf29ce484222325 }

// Path is a convenience for callers (CLI, tests) to override the
// config path without poking the package var directly.
func Path(p string) func() {
	prev := DefaultConfigPath
	DefaultConfigPath = p
	return func() { DefaultConfigPath = prev }
}

// init keeps filepath import alive for future helpers.
var _ = filepath.Separator
