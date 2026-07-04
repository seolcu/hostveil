package tui

import "testing"

func TestLookupTheme_KnownAndFallback(t *testing.T) {
	if LookupTheme(ThemeTokyoNight).Accent != "#7aa2f7" {
		t.Fatalf("tokyo night accent mismatch: %q", LookupTheme(ThemeTokyoNight).Accent)
	}
	if LookupTheme("unknown-theme").Accent != DefaultTheme().Accent {
		t.Fatalf("unknown theme should fall back to default")
	}
}

func TestNormalizeThemeID(t *testing.T) {
	if got := NormalizeThemeID(ThemeNord); got != ThemeNord {
		t.Fatalf("got %q want %q", got, ThemeNord)
	}
	if got := NormalizeThemeID("not-a-theme"); got != ThemeDefault {
		t.Fatalf("got %q want %q", got, ThemeDefault)
	}
}

func TestThemeIDs_IncludesPreferredThemes(t *testing.T) {
	ids := ThemeIDs()
	want := map[string]bool{
		ThemeDefault:    true,
		ThemeTokyoNight: true,
		ThemeCatppuccin: true,
		ThemeNord:       true,
	}
	if len(ids) != len(want) {
		t.Fatalf("expected %d themes, got %d", len(want), len(ids))
	}
	for _, id := range ids {
		if !want[id] {
			t.Fatalf("unexpected theme id %q", id)
		}
	}
}
