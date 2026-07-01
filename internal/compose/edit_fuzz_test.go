package compose

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzOpen writes arbitrary bytes to a temp file and opens it with
// compose.Open. It must never panic, must return either a valid
// File or a yaml parse error wrapped in "yaml parse: %w".
func FuzzOpen(f *testing.F) {
	seeds := []string{
		`services:
  web:
    image: nginx`,
		`{}`,
		``,
		`not yaml: {`,
		`services: [unclosed`,
		`services:
  web:
    image: nginx
    ports:
      - "80:80"`,
		`services:
  web:
    environment:
      - "KEY=value"
    volumes:
      - "./data:/data"`,
		"services:\n  web:\n    image: nginx\n  db:\n    image: postgres\n    depends_on:\n      - web\n",
		`{"unbalanced": [`,
		`%YAML 1.2
---
services:
  web:
    image: nginx`,
		strings.Repeat("x", 4096),
		"\x00\x01\x02",
		`name: myproject
services:
  web:
    image: nginx
    labels:
      - "traefik.enable=true"`,
		`services:
  web:
    image: nginx
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
      interval: 30s
      retries: 3`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "docker-compose.yml")
		if err := osWriteFile(path, []byte(content)); err != nil {
			t.Fatalf("write temp: %v", err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Open panicked on input %q: %v", content, r)
			}
		}()
		file, err := Open(path)
		if err != nil {
			// The only error class is the wrapped yaml parse error
			// (since we wrote the file successfully). Any other
			// error is a regression.
			if !strings.Contains(err.Error(), "yaml parse") {
				t.Errorf("Open returned unexpected error %v for input %q", err, content)
			}
			return
		}
		if file == nil {
			t.Fatalf("Open returned nil file with nil error for input %q", content)
		}
	})
}

// FuzzUnmarshalArbitraryYAML exercises the underlying yaml.v3 decoder
// directly. This is the inner loop of compose.Open — testing it
// independently gives faster fuzz coverage than going through the
// file system. Any panic, out-of-memory, or hang here is a
// regression in the choice of YAML library.
func FuzzUnmarshalArbitraryYAML(f *testing.F) {
	seeds := []string{
		`a: 1`,
		`{}`,
		``,
		`{`,
		`[`,
		`a: &a [1, 2, *a]`,
		`a: !!str 1`,
		strings.Repeat("a:", 1000),
		"\x00",
		"a: |\n  multiline\n  block\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("yaml.Unmarshal panicked: %v", r)
			}
		}()
		var doc yaml.Node
		_ = yaml.Unmarshal([]byte(input), &doc)
		// We don't care about the result; we only assert no panic
		// and that the call returns within a reasonable time (the
		// fuzz harness enforces per-iteration timeouts).
	})
}
