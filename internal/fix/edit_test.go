package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestPickPath_FilePath(t *testing.T) {
	ctx := Context{Finding: &domain.Finding{Metadata: map[string]string{"compose_path": "/compose/path"}}}
	a := Action{FilePath: "/custom/path"}
	got := pickPath(ctx, a)
	if got != "/custom/path" {
		t.Errorf("expected /custom/path, got %q", got)
	}
}

func TestPickPath_ComposePath(t *testing.T) {
	ctx := Context{Finding: &domain.Finding{Metadata: map[string]string{"compose_path": "/compose/path"}}}
	a := Action{}
	got := pickPath(ctx, a)
	if got != "/compose/path" {
		t.Errorf("expected /compose/path, got %q", got)
	}
}

func TestPickPath_Empty(t *testing.T) {
	ctx := Context{Finding: &domain.Finding{Metadata: map[string]string{}}}
	a := Action{}
	got := pickPath(ctx, a)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestSimulateDiff_NonEdit(t *testing.T) {
	a := Action{Type: ActionExec}
	diff, err := SimulateDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "" {
		t.Errorf("expected empty diff for exec action, got %q", diff)
	}
}

func TestSimulateDiff_NoFile(t *testing.T) {
	a := Action{Type: ActionEdit, Apply: func(ctx Context) error { return nil }}
	diff, err := SimulateDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "" {
		t.Errorf("expected empty diff when no file, got %q", diff)
	}
}

func TestSimulateDiff_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}

	a := Action{
		Type:     ActionEdit,
		FilePath: path,
		Apply: func(ctx Context) error {
			return os.WriteFile(path, []byte("after"), 0644)
		},
	}

	diff, err := SimulateDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff == "" {
		t.Fatal("expected non-empty diff")
	}
	if !strings.Contains(diff, "before") && !strings.Contains(diff, "after") {
		t.Errorf("diff should contain file content, got: %s", diff)
	}

	// Verify file was restored (dry-run guarantee)
	data, _ := os.ReadFile(path)
	if string(data) != "before" {
		t.Errorf("expected file restored to 'before', got %q", string(data))
	}
}

func TestCaptureDiff_NonEdit(t *testing.T) {
	a := Action{Type: ActionExec, Apply: func(ctx Context) error { return nil }}
	diff, err := CaptureDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "" {
		t.Errorf("expected empty diff for exec action, got %q", diff)
	}
}

func TestCaptureDiff_NoPath(t *testing.T) {
	a := Action{Type: ActionEdit, Apply: func(ctx Context) error { return nil }}
	diff, err := CaptureDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff != "" {
		t.Errorf("expected empty diff when no path, got %q", diff)
	}
}

func TestCaptureDiff_FileExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("before"), 0644); err != nil {
		t.Fatal(err)
	}

	a := Action{
		Type:     ActionEdit,
		FilePath: path,
		Apply: func(ctx Context) error {
			return os.WriteFile(path, []byte("after"), 0644)
		},
	}

	diff, err := CaptureDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff == "" {
		t.Fatal("expected non-empty diff")
	}

	// Verify file was NOT restored (CaptureDiff is real)
	data, _ := os.ReadFile(path)
	if string(data) != "after" {
		t.Errorf("expected file to remain 'after', got %q", string(data))
	}
}

func TestCaptureDiff_FileNotExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.txt")

	a := Action{
		Type:     ActionEdit,
		FilePath: path,
		Apply: func(ctx Context) error {
			return os.WriteFile(path, []byte("created"), 0644)
		},
	}

	diff, err := CaptureDiff(Context{}, a)
	if err != nil {
		t.Fatal(err)
	}
	if diff == "" {
		t.Fatal("expected non-empty diff for new file")
	}

	data, _ := os.ReadFile(path)
	if string(data) != "created" {
		t.Errorf("expected file content 'created', got %q", string(data))
	}
}

func TestUnifiedDiff_Same(t *testing.T) {
	content := []byte("same content\n")
	diff := unifiedDiff("test.txt", content, content)
	if diff != "" {
		t.Errorf("expected empty diff for identical content, got %q", diff)
	}
}

func TestUnifiedDiff_Different(t *testing.T) {
	before := []byte("line1\nline2\n")
	after := []byte("line1\nline2 modified\n")
	diff := unifiedDiff("test.txt", before, after)
	if diff == "" {
		t.Fatal("expected non-empty diff")
	}
	if !strings.Contains(diff, "test.txt") {
		t.Errorf("diff should contain filename, got: %s", diff)
	}
	if !strings.Contains(diff, "-") || !strings.Contains(diff, "+") {
		t.Errorf("diff should have +/- markers, got: %s", diff)
	}
}
