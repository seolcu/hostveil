package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// nolintDirective matches the linter names a suppression comment lists.
//
// Written as a pattern rather than shown as an example, because an example
// in this file is a directive in this file and this test would find it —
// which it did, on the first run.
var nolintDirective = regexp.MustCompile(`//nolint:([a-z0-9,]+)`)

// Every //nolint has to name a linter that actually runs.
//
// Twenty of them did not. gosec, errcheck and nilerr were suppressed all over
// the tree while none of the three was enabled in .golangci.yaml or run
// anywhere in a workflow — so eighteen carefully written justifications were
// silencing nothing, and nothing new in those categories would ever have been
// caught. A suppression for a linter that does not run is worse than no
// comment at all: it reads as a considered exemption and is an empty gesture.
//
// nolintlint catches the inverse — a directive for an *enabled* linter that
// finds nothing there — but it cannot see this case, because a disabled
// linter reports nothing for it to compare against. This is that blind spot.
func TestEveryNolintNamesALinterThatRuns(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join(repoRoot(t), ".golangci.yaml"))
	if err != nil {
		t.Fatalf("read .golangci.yaml: %v", err)
	}
	enabled := map[string]bool{}
	for _, m := range enabledLinter.FindAllStringSubmatch(string(cfg), -1) {
		enabled[m[1]] = true
	}
	if len(enabled) == 0 {
		t.Fatal("no linters parsed out of .golangci.yaml; this check would pass vacuously")
	}

	root := repoRoot(t)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(b), "\n") {
			for _, m := range nolintDirective.FindAllStringSubmatch(line, -1) {
				for _, name := range strings.Split(m[1], ",") {
					if !enabled[name] {
						t.Errorf("%s:%d suppresses %q, which .golangci.yaml does not enable — "+
							"the directive silences nothing and reads as a considered exemption",
							rel, i+1, name)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
