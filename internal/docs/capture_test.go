package docs

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/ui/theme"
)

// docs/DEVELOPMENT.md carries a table of every palette's ground and ink,
// because ansi2png.py cannot read them off a terminal capture and a screenshot
// of a non-default theme has to be told what they are.
//
// It is the fourth copy of a hex this repository has had to make, and the other
// three are why internal/ui/theme exists at all: the TUI's styles and the
// dashboard's stylesheet each held their own, each claiming in a comment to
// match the other, and they did not. This copy cannot be generated away — it is
// prose, and the whole point of the table is that somebody reads it before
// running a command — so it is pinned instead. A palette adjusted without the
// table following it produces a screenshot with the wrong ground behind it,
// which looks like a rendering bug in hostveil rather than a stale document.
var captureRow = regexp.MustCompile(`^\| ` + "`" + `([a-z]+)` + "`" + `(?: \(default\))? \| ` + "`" + `(#[0-9a-f]{6})` + "`" + ` \| ` + "`" + `(#[0-9a-f]{6})` + "`" + ` \|$`)

func TestTheCaptureTableMatchesThePalettes(t *testing.T) {
	rows := map[string][2]string{}
	for _, line := range strings.Split(readRepoFile(t, "docs/DEVELOPMENT.md"), "\n") {
		if m := captureRow.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			rows[m[1]] = [2]string{m[2], m[3]}
		}
	}
	if len(rows) == 0 {
		t.Fatal("no palette rows found in docs/DEVELOPMENT.md; the table moved or the pattern stopped matching")
	}

	for _, th := range theme.All() {
		got, ok := rows[th.ID]
		if !ok {
			t.Errorf("theme %q has no row in the capture table; a screenshot of it would be rendered on One Dark's ground", th.ID)
			continue
		}
		want := [2]string{strings.ToLower(th.Palette.Ink), strings.ToLower(th.Palette.Bone)}
		if got != want {
			t.Errorf("capture table for %q says BG=%s FG=%s; the palette is Ink=%s Bone=%s",
				th.ID, got[0], got[1], want[0], want[1])
		}
		delete(rows, th.ID)
	}
	for id := range rows {
		t.Errorf("the capture table has a row for %q, which is not a theme; have %s",
			id, strings.Join(theme.IDs(), ", "))
	}
}

// And the other direction on the hooks themselves: the document names four
// environment variables that select a palette or an arrangement, and a renamed
// one would leave the reader running a command that silently captures the
// default.
func TestTheCaptureHookEnvVarsExist(t *testing.T) {
	doc := readRepoFile(t, "docs/DEVELOPMENT.md")
	for _, v := range []struct{ name, file string }{
		{"HOSTVEIL_SNAPSHOT_THEME", "internal/ui/tui/snapshot_test.go"},
		{"HOSTVEIL_SNAPSHOT_LAYOUT", "internal/ui/tui/snapshot_test.go"},
		{"HOSTVEIL_SCREENSHOT_THEME", "internal/ui/web/screenshotserve_test.go"},
		{"HOSTVEIL_SCREENSHOT_LAYOUT", "internal/ui/web/screenshotserve_test.go"},
	} {
		if !strings.Contains(doc, v.name) {
			t.Errorf("docs/DEVELOPMENT.md no longer names %s", v.name)
		}
		if !strings.Contains(readRepoFile(t, v.file), fmt.Sprintf("%q", v.name)) {
			t.Errorf("%s does not read %s; the document tells the reader to set a variable nothing consults", v.file, v.name)
		}
	}
}
