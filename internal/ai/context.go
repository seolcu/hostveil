package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// contextFile holds the operator's own description of this host — "a
// personal media server, want fast security patches more than stability" —
// so an AI judgment can weigh a fix's Benefit/Warning against the situation
// it is actually being asked about, rather than in the abstract.
const contextFile = "ai-context.txt"

// maxContextBytes bounds the file: this is meant to be a sentence or two
// that goes straight into every prompt from here on, not an essay someone
// pastes in once and never rereads.
const maxContextBytes = 2000

// LoadContext reads the saved host description, or "" if none has been set
// (including when dir is empty, matching theme.Load/layout's same
// "no preference recorded" convention).
func LoadContext(dir string) string {
	if dir == "" {
		return ""
	}
	//nolint:gosec // G304: fixed file name under the state directory the caller resolved
	b, err := os.ReadFile(filepath.Join(dir, contextFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SaveContext records the host description, or clears it when text is
// empty. Unlike theme.Save there is no fixed set of valid values to check
// against — any operator-authored sentence is valid — so the only
// validation is the length cap.
func SaveContext(dir, text string) error {
	text = strings.TrimSpace(text)
	if len(text) > maxContextBytes {
		return fmt.Errorf("context is %d bytes, over the %d-byte limit", len(text), maxContextBytes)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, contextFile)
	if text == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, []byte(text+"\n"), 0o600)
}
