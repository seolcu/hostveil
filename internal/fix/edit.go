package fix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// pickPath resolves the target file path for an edit action.
// It checks Action.FilePath first, then falls back to the
// compose_path in the finding's metadata.
func pickPath(ctx Context, a Action) string {
	if a.FilePath != "" {
		return a.FilePath
	}
	return ctx.ComposePath()
}

// SimulateDiff runs an ActionEdit in dry-run mode: it applies the
// edit, captures the diff, then restores the original file.
// Returns empty string if the action type is not ActionEdit or
// the target file cannot be determined.
func SimulateDiff(ctx Context, a Action) (string, error) {
	if a.Type != ActionEdit {
		return "", nil
	}

	path := pickPath(ctx, a)
	if path == "" {
		return "", nil
	}

	original, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}

	// Run the actual Apply (modifies the file)
	applyErr := a.Apply(ctx)

	modified, readErr := os.ReadFile(path)
	if readErr != nil {
		modified = original
	}

	// Always restore original (dry-run guarantee)
	_ = os.WriteFile(path, original, 0644)

	// Clean up any .bak files left by compose edits
	_ = os.Remove(path + ".bak")

	if applyErr != nil {
		return "", applyErr
	}

	return unifiedDiff(path, original, modified), nil
}

// CaptureDiff runs an ActionEdit for real and captures the resulting diff.
// Unlike SimulateDiff, it does NOT restore the original file.
// If no file path is available, it falls back to calling Apply directly
// and returns any diff captured in the context.
func CaptureDiff(ctx Context, a Action) (string, error) {
	if a.Type != ActionEdit {
		return "", nil
	}

	path := pickPath(ctx, a)
	if path == "" {
		// No file to diff — just run Apply and return context diff
		err := a.Apply(ctx)
		if err != nil {
			return "", err
		}
		return ctx.Diff, nil
	}

	original, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist yet (will be created by Apply)
		err = a.Apply(ctx)
		if err != nil {
			return "", err
		}
		modified, readErr := os.ReadFile(path)
		if readErr != nil {
			return "", fmt.Errorf("read modified file after apply: %w", readErr)
		}
		return unifiedDiff(path, nil, modified), nil
	}

	err = a.Apply(ctx)
	if err != nil {
		return "", err
	}

	modified, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return unifiedDiff(path, original, modified), nil
}

func unifiedDiff(path string, before, after []byte) string {
	if bytes.Equal(before, after) {
		return ""
	}

	dir := os.TempDir()
	aFile := filepath.Join(dir, "hostveil.diff.a")
	bFile := filepath.Join(dir, "hostveil.diff.b")

	_ = os.WriteFile(aFile, before, 0644)
	_ = os.WriteFile(bFile, after, 0644)
	defer func() {
		_ = os.Remove(aFile)
		_ = os.Remove(bFile)
	}()

	out, _ := exec.Command("diff", "-u", "--label", "a/"+path, "--label", "b/"+path, aFile, bFile).Output()
	return string(out)
}
