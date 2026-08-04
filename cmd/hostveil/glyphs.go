package main

import (
	"os"
	"strings"

	"github.com/seolcu/hostveil/internal/glyph"
)

// glyphsEnv names the symbol set when no --glyphs flag is given, for shells
// and systemd units that would rather set it once than repeat a flag. It is
// the counterpart of HOSTVEIL_THEME and resolves the same way.
const glyphsEnv = "HOSTVEIL_GLYPHS"

// resolveGlyphs applies the precedence --glyphs > HOSTVEIL_GLYPHS > the
// remembered choice > plain. Only a bad flag value is an error; a stale
// environment variable or preference file falls back silently rather than
// keeping an interface from starting over a font.
func resolveGlyphs(flagValue string) (glyph.Set, error) {
	return glyph.Resolve(flagValue, os.Getenv(glyphsEnv), stateDir())
}

// glyphList renders the available set names for flag help and usage text.
func glyphList() string { return strings.Join(glyph.IDs(), ", ") }
