package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/fix/fixtest"
	"github.com/seolcu/hostveil/internal/model"
)

// checksSlug is the docs page fixActionsMarker's generated content goes
// into, and fixActionsMarker is where it goes — the same shape as
// changelogSlug/changelogMarker, kept as a second pair rather than
// generalized into one, because two is not yet a pattern.
const (
	checksSlug       = "checks"
	fixActionsMarker = "<!--fix-actions-->"
)

// renderFixActions builds the "what each fix actually does" section of the
// checks page: for every finding with a registered fix, what fix.Default()
// actually builds for it, read straight from the registry rather than typed
// out by hand. The checks table's Fix column ("Auto-fix"/"Review") already
// says whether a finding is fixed unattended; this says what running it
// would actually change, so a reader can decide whether "Auto" means safe
// enough for their own host before a single one ever runs.
//
// English only. The Label and Warning strings this renders live in
// internal/fix/*.go with no i18n hook, and this codebase's rule for Korean
// copy is that it is composed natively, not translated clause for clause —
// so a Korean version is a separate piece of writing, not a pass over this
// function's output.
func renderFixActions() (string, error) {
	registry := fix.Default()

	byDomain := map[model.Source][]string{}
	for _, id := range registry.Patterns() {
		src, ok := domainOf(id)
		if !ok {
			return "", fmt.Errorf("fix-actions: %q does not start with a known domain prefix", id)
		}
		byDomain[src] = append(byDomain[src], id)
	}
	for src := range byDomain {
		sort.Strings(byDomain[src])
	}

	var b strings.Builder
	for _, src := range model.AllSources() {
		ids := byDomain[src]
		if len(ids) == 0 {
			continue
		}
		fmt.Fprintf(&b, "          <h3>%s</h3>\n", escText(src.Label()))
		b.WriteString("          <dl class=\"fix-actions\">\n")
		for _, id := range ids {
			entry, err := renderOneFix(registry, id)
			if err != nil {
				return "", err
			}
			b.WriteString(entry)
		}
		b.WriteString("          </dl>\n")
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// domainOf reads the domain prefix off a finding ID ("ssh.rootlogin" ->
// SourceSSH) against model.AllSources(), the one table every domain lookup
// in this codebase is supposed to go through rather than a second one typed
// out here.
func domainOf(id string) (model.Source, bool) {
	prefix, _, ok := strings.Cut(id, ".")
	if !ok {
		return 0, false
	}
	for _, src := range model.AllSources() {
		if src.String() == prefix {
			return src, true
		}
	}
	return 0, false
}

// renderOneFix renders one finding's entry: what fix.Default() builds for
// it, exactly as an operator applying it would see.
//
// registry.Patterns() is what put id here, so Build failing on it is not a
// case to skip past — every registered pattern is supposed to build against
// fixtest.Finding, and TestEveryRegisteredFixIsValid already holds that for
// the whole registry. An error here means this function found a gap that
// test does not cover, and it should fail the site build rather than
// publish a page with a hole in it.
func renderOneFix(registry *fix.Registry, id string) (string, error) {
	fx, ok, err := registry.Build(fixtest.Finding(id))
	if err != nil {
		return "", fmt.Errorf("fix-actions: building %s: %w", id, err)
	}
	if !ok {
		return "", fmt.Errorf("fix-actions: %s is in Patterns() but Build reports no fix", id)
	}

	effective := fx.EffectiveKind()
	kind := kindLabels["en"][effective]
	if kind == "" {
		return "", fmt.Errorf("fix-actions: %s resolved to a kind with no English label: %v", id, effective)
	}
	if len(fx.Actions) == 0 {
		return "", fmt.Errorf("fix-actions: %s built a fix with no actions", id)
	}
	kindClass := "fix-kind"
	if effective == model.RemediationReview {
		kindClass += " review"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "            <dt id=\"fix-%s\"><code>%s</code> <span class=\"%s\">%s</span></dt>\n",
		escAttr(id), escText(id), kindClass, escText(kind))
	b.WriteString("            <dd>\n")
	if len(fx.Actions) == 1 {
		action, err := renderAction(fx.Actions[0], "")
		if err != nil {
			return "", fmt.Errorf("fix-actions: %s: %w", id, err)
		}
		b.WriteString(action)
	} else {
		// Review only: Validate requires at least two actions there, each an
		// independent alternative rather than a sequential step, and
		// Actions[0] is the one `fix --all --review` and every UI preselect —
		// see the Fix doc comment in internal/fix/registry.go.
		b.WriteString("              <ul>\n")
		for i, a := range fx.Actions {
			suffix := ""
			if i == 0 {
				suffix = " (recommended)"
			}
			action, err := renderAction(a, suffix)
			if err != nil {
				return "", fmt.Errorf("fix-actions: %s: %w", id, err)
			}
			b.WriteString("                <li>\n")
			b.WriteString(action)
			b.WriteString("                </li>\n")
		}
		b.WriteString("              </ul>\n")
	}
	b.WriteString("            </dd>\n")
	return b.String(), nil
}

// renderAction renders one action's label and its warning. Both go through
// inline() (changelog.go) rather than a plain escText: register.go writes
// paths and commands in backticks the same way the changelog does, and a
// literal backtick reaching the page unrendered would be the same defect
// checkChangelogSyntax exists to catch on that page.
//
// An exec action with no Warning is an error here rather than a silent gap:
// it is the one Action.Kind with no rollback checkpoint, and every exec
// action registered today already says so in its own words (firewall.go,
// updates.go) — this page's job is to surface that text, not restate it in
// a second sentence next to it. A future exec fix registered without a
// Warning should fail the site build, not publish a blank next to "Review".
func renderAction(a fix.Action, labelSuffix string) (string, error) {
	if a.Kind == fix.ActionExec && a.Warning == "" {
		return "", fmt.Errorf("an exec action (%q) carries no Warning", a.Label)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "              <p>%s%s</p>\n", inline(a.Label), labelSuffix)
	if a.Warning != "" {
		fmt.Fprintf(&b, "              <p class=\"fix-warning\">⚠ %s</p>\n", inline(a.Warning))
	}
	return b.String(), nil
}

// checksFixKindCell matches one row of the checks table's existing 4-column
// shape, up through its Fix column — the same row findingRow (docs_test.go)
// pins, captured so only the Fix cell's text needs replacing. Left as a
// single group up to that cell rather than three, because nothing here
// needs to know the description or severity; changing that shape only where
// this needs it is what keeps two regexes reading the same rows from
// drifting apart.
var checksFixKindCell = regexp.MustCompile(
	`(<tr><td><code>([a-z0-9.\-]+)</code></td>.*?<td>)(Auto-fix|Review)(</td></tr>)`)

// linkFixColumnRows rewrites the checks table's Fix column so "Auto-fix" and
// "Review" link down to the matching entry renderFixActions produced,
// instead of sitting as plain text next to a description of what running it
// does with nothing connecting the two.
//
// This runs on the *rendered* fragment, never on
// content/en/docs/checks.html itself — the source file the table's own
// regex-pinned tests (findingRow, severityCell in docs_test.go) read stays
// exactly as written, so this cannot touch what those tests check. Every
// candidate is re-verified against the registry rather than trusted from
// the row's own hand-typed label, so a row this function cannot back with a
// real entry below is left as plain text instead of becoming a dead link —
// the row read "Auto-fix" was already correct, wiring it to nothing at all
// would not be.
func linkFixColumnRows(html string, registry *fix.Registry) string {
	return checksFixKindCell.ReplaceAllStringFunc(html, func(m string) string {
		sub := checksFixKindCell.FindStringSubmatch(m)
		before, id, kind, after := sub[1], sub[2], sub[3], sub[4]
		if !registry.Has(id) {
			return m
		}
		return before + `<a href="#fix-` + id + `">` + kind + `</a>` + after
	})
}
