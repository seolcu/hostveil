// Package docs fails the build when a published page, a workflow or a
// contributor document drifts from the code it describes.
package docs

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// repoRoot walks up from the test's directory to the module root, so the
// tests read the real files rather than embedded copies that could drift.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the test directory")
		}
		dir = parent
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func addUnique(out []string, s string) []string {
	if s != "" && !slices.Contains(out, s) {
		return append(out, s)
	}
	return out
}
