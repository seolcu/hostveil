package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportRequiresFormat(t *testing.T) {
	fixtureHost(t)
	code, _ := runCmd(t, func() int {
		return cmdExport(context.Background(), nil)
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (usage error) for a missing --format", code)
	}
}

func TestExportRequiresOutputForBinaryFormats(t *testing.T) {
	fixtureHost(t)
	for _, format := range []string{"docx", "pdf"} {
		code, _ := runCmd(t, func() int {
			return cmdExport(context.Background(), []string{"--format", format})
		})
		if code != 2 {
			t.Errorf("--format %s with no --output: exit = %d, want 2", format, code)
		}
	}
}

func TestExportMarkdownToStdoutDescribesTheFinding(t *testing.T) {
	fixtureHost(t)
	code, out := runCmd(t, func() int {
		return cmdExport(context.Background(), []string{"--format", "markdown"})
	})
	// exposedRedis is compose.ds018, High and unfixed at this point in the
	// test — exitFindings (1) is the correct code for that, the same gate
	// scan uses.
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (unfixed High finding)\n%s", code, out)
	}
	if !strings.Contains(out, "# hostveil security report") {
		t.Errorf("stdout is not the Markdown report:\n%s", out)
	}
	if !strings.Contains(out, "compose.ds018") && !strings.Contains(out, "Datastore") {
		t.Errorf("the exposed-redis finding is missing from the export:\n%s", out)
	}
}

func TestExportDOCXWritesABinaryFile(t *testing.T) {
	fixtureHost(t)
	path := filepath.Join(t.TempDir(), "report.docx")
	code, _ := runCmd(t, func() int {
		return cmdExport(context.Background(), []string{"--format", "docx", "--output", path})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 4 || string(data[:2]) != "PK" {
		t.Error("report.docx is not a zip (docx) file")
	}
}

func TestExportRejectsUnknownFormat(t *testing.T) {
	fixtureHost(t)
	code, out := runCmd(t, func() int {
		return cmdExport(context.Background(), []string{"--format", "yaml"})
	})
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, out)
	}
}
