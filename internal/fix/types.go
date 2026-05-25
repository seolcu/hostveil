// Package fix provides the fix engine registry and actions for security findings.
package fix

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type ActionType int

const (
	ActionEdit   ActionType = iota
	ActionExec
	ActionPrompt
)

type Context struct {
	Finding *domain.Finding
	Log     func(string, ...interface{})
	Diff    string
}

func (c Context) ComposePath() string {
	if c.Finding == nil {
		return ""
	}
	return c.Finding.Metadata["compose_path"]
}

type Action struct {
	Type        ActionType
	Label       string
	Description string
	Warning     string
	EditPath    string
	Command     []string
	Apply       func(Context) error
}

type Fix struct {
	FindingID string
	Label     string
	Actions   []Action
}

func (f *Fix) Class() domain.RemediationKind {
	switch {
	case len(f.Actions) == 0:
		return domain.RemediationUnavailable
	case len(f.Actions) > 1:
		return domain.RemediationReview
	case f.Actions[0].Type == ActionPrompt:
		return domain.RemediationManual
	default:
		return domain.RemediationAuto
	}
}

func (f *Fix) Run(ctx Context, actionIdx int) FixResult {
	if actionIdx < 0 || actionIdx >= len(f.Actions) {
		return FixResult{Error: "invalid action index"}
	}
	action := f.Actions[actionIdx]
	err := action.Apply(ctx)
	if err != nil {
		return FixResult{Error: err.Error()}
	}
	return FixResult{Success: true, Label: action.Label, Diff: ctx.Diff}
}

type FixResult struct {
	Success bool
	Error   string
	Label   string
	Diff    string
}

func (r FixResult) String() string {
	if r.Success {
		if r.Diff != "" {
			return fmt.Sprintf("✓ %s\n%s", r.Label, r.Diff)
		}
		return fmt.Sprintf("✓ %s", r.Label)
	}
	return fmt.Sprintf("✗ %s: %s", r.Label, r.Error)
}

type Registry struct {
	entries  map[string]*Fix
	patterns []patternFix
}

type patternFix struct {
	pattern string
	fix     *Fix
}

func New() *Registry {
	return &Registry{entries: map[string]*Fix{}}
}

func (r *Registry) Register(f *Fix) {
	id := strings.ToLower(f.FindingID)
	if strings.ContainsAny(id, "*?[") {
		r.patterns = append(r.patterns, patternFix{pattern: id, fix: f})
		return
	}
	r.entries[id] = f
}

func (r *Registry) Lookup(id string) *Fix {
	key := strings.ToLower(id)
	if f, ok := r.entries[key]; ok {
		return f
	}
	for _, pf := range r.patterns {
		if matched, _ := filepath.Match(pf.pattern, key); matched {
			return pf.fix
		}
	}
	return nil
}

func (r *Registry) Classify(findings []domain.Finding) {
	for i := range findings {
		if f := r.Lookup(findings[i].ID); f != nil {
			findings[i].Remediation = f.Class()
		}
	}
}
