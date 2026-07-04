package tui

import "testing"

func TestLookupTheme_KnownAndFallback(t *testing.T) {
	if LookupTheme(ThemeTokyoNight).Accent != "#7aa2f7" {
		t.Fatalf("tokyo night accent mismatch: %q", LookupTheme(ThemeTokyoNight).Accent)
	}
	if LookupTheme(ThemeDracula).Accent != "#bd93f9" {
		t.Fatalf("dracula accent mismatch: %q", LookupTheme(ThemeDracula).Accent)
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

func TestThemeIDs_IncludesPopularThemes(t *testing.T) {
	ids := ThemeIDs()
	required := []string{
		ThemeDefault,
		ThemeTokyoNight,
		ThemeCatppuccin,
		ThemeNord,
		ThemeDracula,
		ThemeGruvbox,
		ThemeOneDark,
		ThemeSolarized,
		ThemeMonokai,
		ThemeEverforest,
		ThemeRosePine,
		ThemeKanagawa,
		ThemeGitHubDark,
		ThemeAyuDark,
		ThemeNightOwl,
	}
	if len(ids) != len(required) {
		t.Fatalf("expected %d themes, got %d", len(required), len(ids))
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate theme id %q", id)
		}
		seen[id] = true
	}
	for _, id := range required {
		if !seen[id] {
			t.Fatalf("missing theme id %q", id)
		}
	}
}

func TestThemeLabel_KnownThemes(t *testing.T) {
	if got := ThemeLabel(ThemeRosePine); got != "Rosé Pine" {
		t.Fatalf("got label %q", got)
	}
	if got := ThemeLabel("missing"); got != "missing" {
		t.Fatalf("unknown label should echo id, got %q", got)
	}
}
