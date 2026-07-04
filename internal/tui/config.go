package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds persisted TUI preferences.
type Config struct {
	Theme string `json:"theme"`
}

// LoadConfig reads preferences from the hostveil config file.
func LoadConfig() Config {
	path, err := configPath()
	if err != nil {
		return Config{Theme: ThemeDefault}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{Theme: ThemeDefault}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{Theme: ThemeDefault}
	}
	cfg.Theme = NormalizeThemeID(cfg.Theme)
	return cfg
}

// SaveConfig writes preferences to the hostveil config file.
func SaveConfig(cfg Config) error {
	cfg.Theme = NormalizeThemeID(cfg.Theme)
	path, err := configPath()
	if err != nil {
		return fmt.Errorf("config path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func configPath() (string, error) {
	if override := os.Getenv("HOSTVEIL_CONFIG_DIR"); override != "" {
		return filepath.Join(override, "config.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hostveil", "config.json"), nil
}
