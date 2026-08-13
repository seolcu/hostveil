package clirender

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/glyph"
	"github.com/seolcu/hostveil/internal/ui/uitest"
)

// TestSnapshotDump writes the CLI's rendering of the published fixture into
// HOSTVEIL_SNAPSHOT, and is a no-op in normal test runs.
//
// It is the third leg of a hook the other two surfaces already had — the TUI's
// TestSnapshotDump and the dashboard's TestScreenshotServe — and it exists for
// the reason those do: a picture of the interface should come from a host that
// is written down rather than from whichever machine somebody happened to have
// to hand. The CLI was the surface without one, so the only way to capture it
// was to run a real scan, which means the capture carries a real host's
// findings and cannot be reproduced by the next person to change the output.
//
// It renders the same uitest.PublishedReport the other two draw, so all three
// pictures are of one host.
//
//	HOSTVEIL_SNAPSHOT=/tmp/cli go test ./internal/clirender -run TestSnapshotDump
func TestSnapshotDump(t *testing.T) {
	dir := os.Getenv("HOSTVEIL_SNAPSHOT")
	if dir == "" {
		t.Skip("set HOSTVEIL_SNAPSHOT to a directory to dump the CLI renderings")
	}
	rep := uitest.PublishedReport()

	// Colour on and off, plain and Nerd glyphs, terse and verbose: the four
	// shapes the CLI actually prints. --json is deliberately not here — it has
	// its own tests and a screenshot of it says nothing a `jq` output would not.
	for _, c := range []struct {
		name string
		opts Options
	}{
		{"01-scan", Options{Color: true, Glyphs: glyph.Plain}},
		{"02-scan-verbose", Options{Color: true, Verbose: true, Glyphs: glyph.Plain}},
		{"03-scan-nerd", Options{Color: true, Glyphs: glyph.Nerd}},
		{"04-scan-nocolor", Options{Glyphs: glyph.Plain}},
	} {
		path := filepath.Join(dir, c.name+".ans")
		if err := os.WriteFile(path, []byte(Text(rep, c.opts)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
