package web

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Colour in this design system means one of three things, and structure is
// the newest of them: which panel this is, where you are, and how to move.
// The terminal spends the accent on exactly that, and the dashboard has to
// agree, because they are one product with two renderers rather than two
// products.
//
// Agreeing is not something either side can check about the other — one is
// Go and one is a stylesheet — so what is checkable is that the dashboard is
// consistent with itself. It was not: the accent landed on the findings pane
// header and on the filter chip, and the rail's own header two hundred pixels
// to the left stayed the muted grey it had always been. One panel title blue,
// the other grey, on the same screen. The rail's marker for the domain you
// are filtered to was the same omission — bone where the terminal's "›" had
// become the accent.
//
// The failure mode is worth naming because it is not a broken page: it is a
// page that looks deliberate and says something untrue about what the colours
// mean.
//
// Every structural rule is listed, not just the one that was wrong. Pinning
// the rail's header alone would pass the day somebody moved the findings
// header back to slate and left the two disagreeing from the other side.
func TestStructureRolesUseOneColourAcrossTheDashboard(t *testing.T) {
	css := readAppCSS(t)

	// Every rule the dashboard uses to say "this is a panel" or "you are
	// here". Which property carries the colour differs — the headers set it on
	// the text, the chip inverts and sets it as a background, the rail's
	// marker paints a left edge — so what is asserted is that the accent is in
	// the rule at all, and that no heat is.
	for _, sel := range []string{
		".pane-head",       // the findings panel's title
		".rail .rail-head", // and the domains panel's, two hundred pixels left of it
		".chip.on",         // the filter you are looking through
		".rail .dom.on",    // the domain that filter names
		".detail .howto",   // every heading inside the detail pane
	} {
		roles := rolesIn(ruleFor(t, css, sel))
		if !roles["--accent"] {
			t.Errorf("%s paints with %v and not the accent. Structure is what the "+
				"accent is for, and a panel title in the muted grey of the text under "+
				"it is the omission this test was written for: the rail's header "+
				"stayed slate while the findings header beside it turned blue, which "+
				"reads as a difference in kind rather than in position.", sel, keys(roles))
		}
		for _, heat := range []string{"--crit", "--high", "--med", "--low", "--safe"} {
			if roles[heat] {
				t.Errorf("%s paints with %s; the heats are spoken for by risk and "+
					"safety, and structure may not borrow one", sel, heat)
			}
		}
	}
}

// rolesIn is every palette variable a declaration block paints with.
func rolesIn(rule string) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`var\((--[a-z0-9-]+)\)`).FindAllStringSubmatch(rule, -1) {
		out[m[1]] = true
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ruleFor returns the declaration block of the first rule whose selector list
// contains selector.
func ruleFor(t *testing.T, css, selector string) string {
	t.Helper()
	for i := 0; i < len(css); {
		open := strings.Index(css[i:], "{")
		if open < 0 {
			break
		}
		open += i
		end := strings.Index(css[open:], "}")
		if end < 0 {
			break
		}
		end += open
		head := strings.TrimSpace(css[i:open])
		for _, s := range strings.Split(head, ",") {
			if strings.TrimSpace(s) == selector {
				return css[open+1 : end]
			}
		}
		i = end + 1
	}
	t.Fatalf("app.css has no rule for %q; if it was renamed, rename it here too", selector)
	return ""
}

func readAppCSS(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/app.css")
	if err != nil {
		t.Fatalf("reading app.css: %v", err)
	}
	return string(b)
}
