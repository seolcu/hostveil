package report

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

// WriteJSON serializes r as JSON and writes it to w with a trailing
// newline. The output matches contracts/report.md §"JSON report
// shape".
func WriteJSON(w io.Writer, r Run) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	_, err := w.Write([]byte("\n"))
	return err
}

func stdout() *os.File { return os.Stdout }

func ensureDir(p string) error {
	if p == "" {
		return nil
	}
	return os.MkdirAll(p, 0o755)
}

func writeFile(p string, fn func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()
	return fn(f)
}
