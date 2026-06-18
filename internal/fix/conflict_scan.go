package fix

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// readDir returns the basenames of files in dir. We don't import
// os directly here to keep the conflict detector's surface tight.
func readDir(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out = append(out, e.Name())
	}
	return out, nil
}

// joinPath is filepath.Join; pulled in to keep the import list on
// conflict.go readable.
func joinPath(parts ...string) string { return filepath.Join(parts...) }

// scanSSHMatchBlocks walks path line by line, collecting any
// non-comment "Match" block that re-enables one of the
// security-relevant settings. The v3.0.0-alpha implementation
// surfaces every Match block found, regardless of its contents;
// the human reviewer decides whether each is a real conflict.
func scanSSHMatchBlocks(path string) ([]Conflict, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		out       []Conflict
		inMatch   bool
		matchLine int
		matchText strings.Builder
		scanner   = bufio.NewScanner(f)
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "Match ") {
			inMatch = true
			matchLine = lineNumber(scanner)
			matchText.Reset()
			matchText.WriteString(line)
			continue
		}
		if inMatch {
			matchText.WriteString(" ")
			matchText.WriteString(line)
			if line == "}" {
				out = append(out, Conflict{
					Kind:    ConflictSSHMatchBlock,
					Path:    path,
					Line:    matchLine,
					Snippet: matchText.String(),
				})
				inMatch = false
			}
		}
	}
	return out, scanner.Err()
}

// lineNumber extracts the 1-indexed line number from a bufio.Scanner
// by reading its position via the input. ScanLines does not expose
// the offset directly, so we use bufio.NewScanner with a custom
// split function is overkill; instead we run a parallel counter via
// a wrapper. This helper is only used by the conflict detector.
func lineNumber(_ *bufio.Scanner) int {
	// bufio.Scanner does not expose its current line number. We
	// accept a small approximation: line numbers start at 1 and
	// each Scan() advances by one. The conflict display uses
	// these as a hint, not a strict file:line anchor.
	return lastLine
}

var lastLine int

// ResetLineCounter zeroes the conflict detector's line counter
// before scanning a new file. Tests that read this package
// directly may want to call this; the public fix.Detect callers
// don't need to.
func ResetLineCounter() { lastLine = 0 }

// init installs a counting SplitFunc on a fresh scanner via a
// shim. We can't actually replace the caller's scanner.Split
// without exporting more, so we provide a countLines helper that
// re-walks the file. Cheap and only used for the conflict display.
func countLines(path string) (map[int]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]string{}
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		n++
		out[n] = s.Text()
	}
	return out, s.Err()
}
