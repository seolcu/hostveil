package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOSTVEIL_CONFIG_DIR", dir)

	if err := SaveConfig(Config{Theme: ThemeCatppuccin}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	cfg := LoadConfig()
	if cfg.Theme != ThemeCatppuccin {
		t.Fatalf("got theme %q want %q", cfg.Theme, ThemeCatppuccin)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), ThemeCatppuccin) {
		t.Fatalf("config file missing theme: %s", raw)
	}
}

func TestLoadConfig_InvalidThemeFallsBack(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOSTVEIL_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"theme":"bogus"}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := LoadConfig()
	if cfg.Theme != ThemeDefault {
		t.Fatalf("got theme %q want %q", cfg.Theme, ThemeDefault)
	}
}
