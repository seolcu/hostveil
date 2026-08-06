package web

import (
	"fmt"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

// The dashboard builds every severity-carrying class name at runtime from
// the model's own table — sevName gives .finding.<name> and
// .over-chip.sev-<name>, sevAbbr gives .chip.c-<abbr>. The stylesheet does
// not: it is a static file with those class names typed into it.
//
// So renaming a level breaks the two apart silently. Nothing fails to
// compile, no test that builds its input from the tables notices, and the
// page still renders — with the severity gutters, the filter chips and the
// overview chips drawn in the default colour, which reads as a theme that
// happens to be low-contrast rather than as a stylesheet that no longer
// matches anything.
//
// That is not hypothetical. It shipped: the landing page's mockup chips
// (site/styles.css) went unstyled for a release the same way, because
// nothing checked them either.
//
// This walks model.AllSeverities and requires a rule for each, so a level
// added, removed, or renamed fails here before it can reach a browser.
func TestTheStylesheetStylesEverySeverityTheModelDeclares(t *testing.T) {
	css, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatal(err)
	}
	sheet := string(css)

	for _, sev := range model.AllSeverities() {
		// Every construction site in app.js, named by what it draws, so a
		// reader chasing a failure lands in the right place. The list was
		// four of these while the comment above already promised the set —
		// and the two it missed are the ones nobody looks at, which is
		// exactly why they need a test rather than a reading.
		for _, want := range []string{
			fmt.Sprintf(".finding.%s", sev.String()),       // per-finding gutter
			fmt.Sprintf(".over-chip.sev-%s", sev),          // overview chips
			fmt.Sprintf(".chip.c-%s", sev.Abbr()),          // filter chips
			fmt.Sprintf(".lane-head.%s", sev.String()),     // the lanes layout
			fmt.Sprintf(".over-jump-row .sev.%s", sev),     // the most-severe list
			fmt.Sprintf(".rail .dom .c .%s", sev.String()), // per-domain counts on the rail
		} {
			if !strings.Contains(sheet, want) {
				t.Errorf("app.css has no rule for %q — the dashboard builds that class name "+
					"from the model at runtime, so %s renders unstyled", want, sev)
			}
		}
	}
}

// And the reverse, for the one spelling that is not derived from a name:
// the abbreviation. .chip.c-<abbr> is the only place the abbreviation
// reaches CSS, and an abbreviation changed without the stylesheet leaves a
// rule that matches nothing while the chip it was for goes plain.
func TestNoSeverityChipRuleIsOrphaned(t *testing.T) {
	css, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatal(err)
	}

	live := map[string]bool{}
	for _, sev := range model.AllSeverities() {
		live[sev.Abbr()] = true
	}

	for _, line := range strings.Split(string(css), "\n") {
		for _, part := range strings.Split(line, ".chip.c-") {
			if part == line {
				continue // no occurrence on this line
			}
			abbr := part
			if i := strings.IndexAny(abbr, ". {,:"); i >= 0 {
				abbr = abbr[:i]
			}
			if abbr != "" && !live[abbr] {
				t.Errorf("app.css styles .chip.c-%s and no severity abbreviates to %q, "+
					"so that rule matches nothing and some chip is unstyled", abbr, abbr)
			}
		}
	}
}
