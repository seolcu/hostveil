package fix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
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
	var originalMode os.FileMode
	if info, statErr := os.Stat(path); statErr == nil {
		originalMode = info.Mode()
	} else {
		originalMode = 0644
	}

	// Run the actual Apply (modifies the file)
	applyErr := a.Apply(ctx)

	modified, readErr := os.ReadFile(path)
	if readErr != nil {
		modified = original
	}

	// Always restore original (dry-run guarantee)
	_ = os.WriteFile(path, original, originalMode)

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

	aFile, err := os.CreateTemp("", "hostveil-diff-a-*")
	if err != nil {
		return ""
	}
	bFile, err2 := os.CreateTemp("", "hostveil-diff-b-*")
	if err2 != nil {
		aFile.Close()
		os.Remove(aFile.Name())
		return ""
	}

	// Write both sides of the diff to temp files. If these fail, the
	// diff command below will produce an empty or partial result, which
	// is acceptable for a diff utility.
	_ = os.WriteFile(aFile.Name(), before, 0644)
	_ = os.WriteFile(bFile.Name(), after, 0644)
	aFile.Close()
	bFile.Close()
	defer func() {
		// Best-effort cleanup of temp files; failure is safe to ignore.
		_ = os.Remove(aFile.Name())
		_ = os.Remove(bFile.Name())
	}()

	out, err := exec.Command("diff", "-u", "--label", "a/"+path, "--label", "b/"+path, aFile.Name(), bFile.Name()).Output()
	if err == nil {
		return ""
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return string(out)
	}
	return ""
}
