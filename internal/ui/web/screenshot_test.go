package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/ui/theme"
)

// stampPath records what site/assets/web.png was a picture of.
const stampPath = "testdata/web-shot.stamp"

// TestDashboardScreenshotStampIsCurrent is the same alarm the TUI frame gets,
// built the only way it can be built here.
//
// internal/ui/tui pins its published screenshot by re-rendering the frame and
// comparing: the TUI draws into a string, so the test can produce the exact
// thing the picture was made from. The dashboard cannot be pinned that way.
// Its screenshot is a browser rendering a page, and there is no headless
// browser in this test suite — docs/DEVELOPMENT.md tells a human to take it
// with Firefox against the demo VM.
//
// So this pins the *inputs* instead. Everything that decides what that page
// looks like is either an embedded asset or generated in Go, and hashing all
// of them together answers a narrower question than "is the picture right":
// it answers "has anything that decides what the picture shows changed since
// somebody last looked". That is weaker than the TUI's check and it is the
// strongest check available, and it beats the status quo, where the answer
// was nothing at all and site/assets/tui.png stayed wrong for two releases.
//
// A hash cannot say what moved, so the failure prints each input's own digest
// beside the recorded one — which narrows a re-shoot to "the stylesheet
// changed" rather than "something did".
//
// After re-taking the screenshot, update the stamp:
//
//	HOSTVEIL_UPDATE_STAMP=1 go test ./internal/ui/web -run TestDashboardScreenshotStampIsCurrent
func TestDashboardScreenshotStampIsCurrent(t *testing.T) {
	inputs := screenshotInputs(t)

	var b strings.Builder
	for _, in := range inputs {
		fmt.Fprintf(&b, "%s %s\n", in.digest, in.name)
	}
	current := b.String()

	if os.Getenv("HOSTVEIL_UPDATE_STAMP") != "" {
		if err := os.WriteFile(stampPath, []byte(current), 0o600); err != nil {
			t.Fatalf("write the stamp: %v", err)
		}
		t.Log("stamp updated; commit it beside the re-taken screenshot")
		return
	}

	recorded, err := os.ReadFile(stampPath)
	if err != nil {
		t.Fatalf("read the stamp: %v", err)
	}
	if string(recorded) == current {
		return
	}

	was := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(recorded)), "\n") {
		if digest, name, ok := strings.Cut(line, " "); ok {
			was[name] = digest
		}
	}
	var moved []string
	for _, in := range inputs {
		if old, ok := was[in.name]; !ok {
			moved = append(moved, in.name+" (new)")
		} else if old != in.digest {
			moved = append(moved, in.name)
		}
	}

	t.Errorf("site/assets/web.png is a picture of a dashboard that has since changed.\n"+
		"Changed: %s\n\n"+
		"Re-take it (docs/DEVELOPMENT.md has the command), then:\n"+
		"  HOSTVEIL_UPDATE_STAMP=1 go test ./internal/ui/web -run TestDashboardScreenshotStampIsCurrent",
		strings.Join(moved, ", "))
}

type screenshotInput struct{ name, digest string }

// screenshotInputs is everything that decides what the dashboard looks like.
//
// The generated three are what make this worth having: /model.js carries the
// severity and domain tables the page renders its chips and rail from, and
// /themes.css and /theme.js carry every colour. A severity renamed or a
// domain added moves all of them, and each is exactly the kind of change that
// left the terminal screenshot stale.
func screenshotInputs(t *testing.T) []screenshotInput {
	t.Helper()
	out := []screenshotInput{
		{"model.js", digest(modelJS())},
		{"themes.css", digest(theme.CSS(theme.Default().ID))},
		{"theme.js", digest(theme.JS(theme.Default().ID))},
	}
	for _, name := range []string{"index.html", "app.css", "app.js"} {
		b, err := assets.ReadFile("assets/" + name)
		if err != nil {
			t.Fatalf("read embedded %s: %v", name, err)
		}
		out = append(out, screenshotInput{name, digest(string(b))})
	}
	return out
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}
