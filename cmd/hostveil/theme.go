package main

import (
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/ui/theme"
)

// themeEnv names the theme when no --theme flag is given, for shells and
// systemd units that would rather set it once than repeat a flag.
const themeEnv = "HOSTVEIL_THEME"

// stateDir is where the remembered theme lives — the same per-user (or
// system, when root) directory the checkpoints do. It is resolved here rather
// than inside the UIs: internal/ui may not import internal/history, and this
// is the one place that already may.
func stateDir() string { return history.DefaultDir() }

// resolveTheme applies the precedence --theme > HOSTVEIL_THEME > the
// remembered choice > the default. Only a bad flag value is an error; a stale
// environment variable or preference file falls back silently rather than
// keeping the interface from starting.
func resolveTheme(flagValue string) (theme.Theme, error) {
	return theme.Resolve(flagValue, os.Getenv(themeEnv), stateDir())
}

// themeList renders the available theme IDs for flag help and usage text.
func themeList() string { return strings.Join(theme.IDs(), ", ") }
