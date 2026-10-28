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

// resolveGlyphs applies the precedence --glyphs > HOSTVEIL_GLYPHS > plain.
// Only a bad flag value is an error.
func resolveGlyphs(flagValue string) (glyph.Set, error) {
	return glyph.Resolve(flagValue, os.Getenv(glyphsEnv))
}

// glyphList renders the available set names for flag help and usage text.
func glyphList() string { return strings.Join(glyph.IDs(), ", ") }
