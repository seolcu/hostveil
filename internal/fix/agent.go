package fix

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/json5"
	"github.com/seolcu/hostveil/internal/model"
)

// registerAgent wires the agent-runtime fixes into the registry.
//
// Two shapes. The mode findings chmod a path under the runtime's state
// directory; the config-key findings rewrite one value in the runtime's own
// config file, which became possible when internal/json5 arrived — see
// Default's doc comment for what that unblocked and what it did not.
//
// Exact IDs, not an "agent.*" glob, for the same reason registerFilePerms
// spells its five out: TestEveryRegisteredFixIsValid rejects globs so that
// widening what the registry claims to fix is a deliberate act. It matters
// more here than anywhere: three of this domain's findings are still
// declined, and a glob would silently claim them.
func registerAgent(r *Registry) {
	for _, id := range []string{
		"agent.config-perms",
		"agent.secret-exposed",
	} {
		r.Register(id, buildTightenMode)
	}
	for _, id := range []string{
		"agent.exec-unrestricted",
		"agent.elevated-enabled",
		"agent.control-ui-insecure",
		"agent.ssrf-private-network",
	} {
		r.Register(id, buildAgentConfigKey)
	}
}

// buildAgentConfigKey rewrites the config keys the checker named.
//
// Everything it needs comes from evidence: "config" is the file, "set" is the
// assignment list that settles the finding, and "set-alt" is a second,
// independent alternative where the safe value is a choice rather than a
// single answer. The values are not re-derived here, because internal/fix
// cannot import the checker and a second table of what "safe" means is a
// second answer to the question.
//
// A finding whose evidence carries no "set" is an error rather than a fix
// assembled from a guess. That is the same refusal sysctlPairs makes, and it
// is what keeps agent.sandbox-off — whose safe value nothing in hostveil
// knows — from being handed a value invented at this layer.
func buildAgentConfigKey(f model.Finding) (Fix, error) {
	path := f.Evidence["config"]
	if path == "" {
		return Fix{}, fmt.Errorf("finding %s carries no 'config' evidence, so there is no file to edit", f.ID)
	}
	primary, err := agentAssignments(f, "set")
	if err != nil {
		return Fix{}, err
	}

	root := f.Evidence["root"]
	if root == "" {
		root = pathRoot(path) // compatibility for findings built by older callers
	}
	actions := []Action{agentEditAction(root, path, primary)}
	kind := model.RemediationAuto
	if f.Evidence["set-alt"] != "" {
		alt, err := agentAssignments(f, "set-alt")
		if err != nil {
			return Fix{}, err
		}
		actions = append(actions, agentEditAction(root, path, alt))
		kind = model.RemediationReview
	}

	return Fix{
		Label:   "Correct " + strings.Join(keysOfAssignments(primary), ", ") + " in " + path,
		Kind:    kind,
		Actions: actions,
	}, nil
}

// agentEditAction is one alternative: set every named key to its value in the
// runtime's config, preserving the rest of the file byte for byte.
func agentEditAction(root, path string, as []assignment) Action {
	return Action{
		Label: "Set " + strings.Join(renderAssignments(as), ", "),
		Kind:  ActionEdit,
		Path:  path,
		// The path is under a user's home, and the account owns every
		// component of it. See fix.Action.NoFollow.
		NoFollow: true,
		SafeRoot: root,
		// No VerifyCmd: neither runtime ships a config validator, and there
		// is nothing on the host that would answer. The equivalent guarantee
		// is inside the transform — json5.Doc.Bytes re-parses what it
		// produced and refuses to return it unless the tree matches the
		// original with exactly these keys changed. An sshd -t answers "will
		// the service accept this"; this answers "did the edit do only what
		// it said", which is the claim that can be made here.
		Transform: func(in []byte) ([]byte, error) {
			doc, err := json5.Load(in)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", path, err)
			}
			for _, a := range as {
				if !doc.Has(a.key) {
					// The key was there when the scan read it. That it is
					// not there now means the file changed underneath, and
					// writing anything on that basis would be a fix aimed at
					// a config nobody has looked at.
					return nil, fmt.Errorf("%s no longer sets %s; re-scan before fixing", path, a.key)
				}
				if err := doc.Set(a.key, a.value); err != nil {
					return nil, err
				}
			}
			return doc.Bytes()
		},
	}
}

func pathRoot(path string) string {
	// Agent findings carry an absolute config path below <home>/.openclaw or
	// <home>/.hermes. The runtime directory is the first component controlled
	// by that account; its parent is the trusted home root.
	return filepath.Dir(filepath.Dir(path))
}

// assignment is one key and the value it should take.
type assignment struct {
	key   string
	value any
}

// agentAssignments parses one evidence field into assignments. The value of
// each pair is a JSON literal, which is what keeps `false` distinguishable
// from `"false"` across a string the checker and the fix both have to agree
// on.
func agentAssignments(f model.Finding, field string) ([]assignment, error) {
	raw := f.Evidence[field]
	if raw == "" {
		return nil, fmt.Errorf("finding %s carries no %q evidence, so there is no value to write", f.ID, field)
	}
	var out []assignment
	for _, pair := range strings.Split(raw, model.EvidenceSeparator) {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, lit, ok := strings.Cut(pair, "=")
		if !ok || k == "" || lit == "" {
			return nil, fmt.Errorf("finding %s has malformed %q evidence %q", f.ID, field, raw)
		}
		var v any
		if err := json.Unmarshal([]byte(lit), &v); err != nil {
			return nil, fmt.Errorf("finding %s has a %q value that is not a JSON literal: %q", f.ID, field, lit)
		}
		out = append(out, assignment{key: k, value: v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("finding %s has empty %q evidence", f.ID, field)
	}
	return out, nil
}

func keysOfAssignments(as []assignment) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.key)
	}
	return out
}

// renderAssignments spells each pair the way it will appear in the file, so
// the action label and the diff say the same thing.
func renderAssignments(as []assignment) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		b, err := json.Marshal(a.value)
		if err != nil {
			out = append(out, a.key)
			continue
		}
		out = append(out, a.key+" to "+string(b))
	}
	return out
}
