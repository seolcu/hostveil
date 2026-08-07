package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These mirror internal/ui/theme/pref_test.go deliberately. The arrangement
// preference had none of this: it was loaded and saved by hand in
// cmd/hostveil, at 0% coverage, and the one property anybody would notice
// breaking — that the picker's choice comes back next time — was held up by
// nothing.

func TestSaveThenLoadRoundTrips(t *testing.T) {
	dir := t.TempDir()
	want := Layouts()[len(Layouts())-1].ID // not the default, or the test proves nothing
	if want == DefaultLayout().ID {
		t.Fatal("the registry has one arrangement; this test needs two to say anything")
	}
	if err := SaveLayoutPref(dir, want); err != nil {
		t.Fatal(err)
	}
	if got := LoadLayoutPref(dir); got != want {
		t.Errorf("LoadLayoutPref = %q, want %q — the picker's choice did not come back", got, want)
	}
	fi, err := os.Stat(filepath.Join(dir, layoutPrefFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("preference file mode is %v, want 0600", fi.Mode().Perm())
	}
}

func TestSaveRefusesAnUnknownArrangement(t *testing.T) {
	dir := t.TempDir()
	err := SaveLayoutPref(dir, "not-an-arrangement")
	if err == nil {
		t.Fatal("SaveLayoutPref wrote an arrangement that does not exist")
	}
	if !strings.Contains(err.Error(), "not-an-arrangement") {
		t.Errorf("error does not name what was asked for: %v", err)
	}
	// And every real one, so the message tells the reader what to type.
	for _, id := range LayoutIDs() {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error does not list %q among the available arrangements: %v", id, err)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, layoutPrefFile)); !os.IsNotExist(statErr) {
		t.Error("a refused save still wrote the file")
	}
}

// A preference written by a build that had an arrangement this one does not
// must read as "no preference", not as an error and not as that arrangement.
func TestLoadIgnoresARetiredArrangement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layoutPrefFile), []byte("retired-arrangement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadLayoutPref(dir); got != "" {
		t.Errorf("LoadLayoutPref = %q for an arrangement that does not exist, want \"\"", got)
	}
}

func TestLoadToleratesWhitespaceAndAbsence(t *testing.T) {
	dir := t.TempDir()
	id := Layouts()[1].ID
	if err := os.WriteFile(filepath.Join(dir, layoutPrefFile), []byte("  "+id+" \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadLayoutPref(dir); got != id {
		t.Errorf("LoadLayoutPref = %q, want %q — a trailing newline is not a different arrangement", got, id)
	}
	if got := LoadLayoutPref(t.TempDir()); got != "" {
		t.Errorf("LoadLayoutPref on a directory with no preference = %q, want \"\"", got)
	}
	if got := LoadLayoutPref(""); got != "" {
		t.Errorf("LoadLayoutPref(\"\") = %q, want \"\" — no state directory is not an error", got)
	}
}

// The precedence is the whole point of the change, so it is tested as a
// precedence rather than one layer at a time: each layer must beat every
// layer below it while all of them are set.
func TestResolveLayoutPrecedence(t *testing.T) {
	ids := LayoutIDs()
	if len(ids) < 4 {
		t.Fatalf("this test needs four distinct arrangements, the registry has %d", len(ids))
	}
	flagID, envID, prefID := ids[1], ids[2], ids[3]

	dir := t.TempDir()
	if err := SaveLayoutPref(dir, prefID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name             string
		flag, env, dir   string
		want             string
		wantErrSubstring string
	}{
		{name: "flag beats everything", flag: flagID, env: envID, dir: dir, want: flagID},
		{name: "env beats the saved preference", env: envID, dir: dir, want: envID},
		{name: "the saved preference beats the default", dir: dir, want: prefID},
		{name: "nothing set falls back to the shipped default", want: DefaultLayout().ID},
		{
			name: "a bad flag is an error, because it was just typed",
			flag: "nope", env: envID, dir: dir,
			want: DefaultLayout().ID, wantErrSubstring: "nope",
		},
		{
			name: "a bad environment value falls through silently",
			env:  "nope", dir: dir, want: prefID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveLayout(tc.flag, tc.env, tc.dir)
			if tc.wantErrSubstring == "" {
				if err != nil {
					t.Fatalf("ResolveLayout returned %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("ResolveLayout accepted a value it should have refused")
				}
				if !strings.Contains(err.Error(), tc.wantErrSubstring) {
					t.Errorf("error %v does not mention %q", err, tc.wantErrSubstring)
				}
			}
			if got.ID != tc.want {
				t.Errorf("ResolveLayout = %q, want %q", got.ID, tc.want)
			}
		})
	}
}
