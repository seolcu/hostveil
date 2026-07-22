package theme

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state") // does not exist yet
	if err := Save(dir, "nord"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := Load(dir); got != "nord" {
		t.Errorf("Load = %q, want nord", got)
	}

	fi, err := os.Stat(filepath.Join(dir, prefFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("preference file mode = %v, want 0600", perm)
	}
}

func TestSaveRefusesUnknown(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, "no-such-theme"); err == nil {
		t.Fatal("Save accepted an unknown theme")
	}
	if _, err := os.Stat(filepath.Join(dir, prefFile)); !os.IsNotExist(err) {
		t.Error("Save wrote a file for an unknown theme")
	}
}

// A missing, unreadable, or stale preference must read as "no preference"
// rather than as an error a UI has to handle before it can draw anything.
func TestLoadTolerant(t *testing.T) {
	dir := t.TempDir()
	if got := Load(dir); got != "" {
		t.Errorf("Load of an empty dir = %q, want \"\"", got)
	}
	if got := Load(""); got != "" {
		t.Errorf("Load(\"\") = %q, want \"\"", got)
	}
	if err := os.WriteFile(filepath.Join(dir, prefFile), []byte("retired-theme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Load(dir); got != "" {
		t.Errorf("Load of a retired theme = %q, want \"\"", got)
	}
}

// Trailing whitespace is what an operator's editor leaves behind. It must not
// turn a valid preference into an unknown one.
func TestLoadTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prefFile), []byte("  gruvbox \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Load(dir); got != "gruvbox" {
		t.Errorf("Load = %q, want gruvbox", got)
	}
}

func TestResolvePrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := Save(dir, "catppuccin"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		flag, env, dir string
		want           string
		wantErr        bool
	}{
		{name: "flag wins", flag: "nord", env: "gruvbox", dir: dir, want: "nord"},
		{name: "env beats saved", env: "gruvbox", dir: dir, want: "gruvbox"},
		{name: "saved beats default", dir: dir, want: "catppuccin"},
		{name: "nothing set", want: Default().ID},
		{name: "unknown env falls back to saved", env: "bogus", dir: dir, want: "catppuccin"},
		{name: "unknown flag is an error", flag: "bogus", dir: dir, want: Default().ID, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Resolve(tc.flag, tc.env, tc.dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Resolve error = %v, wantErr %v", err, tc.wantErr)
			}
			if got.ID != tc.want {
				t.Errorf("Resolve = %q, want %q", got.ID, tc.want)
			}
		})
	}
}

// The error for a mistyped --theme has to say what the user could have typed
// instead; a bare "unknown theme" leaves them guessing at five names.
func TestUnknownThemeErrorListsIDs(t *testing.T) {
	_, err := Resolve("bogus", "", "")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, id := range IDs() {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error %q does not mention %q", err, id)
		}
	}
}
