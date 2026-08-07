package main

import (
	"os"

	"github.com/seolcu/hostveil/internal/ui/tui"
)

// This file is the arrangement's half of what theme.go does for the palette,
// and it is deliberately as thin: the registry, the validation and the
// precedence live in internal/ui/tui, where a test can reach them and where
// an ID can be checked against the list it came from.
//
// It used to hold the loading and saving itself, with no environment layer,
// because the arrangement picker shipped as an experiment and this file said
// so — "temporary ... when that is decided, this file goes." It was decided:
// C · Console is the default and the other five stayed. What the experiment's
// scaffolding left behind was an arrangement you could set with a flag or a
// keypress and not with an environment variable, which is the one way you set
// something for a systemd unit or a shell profile.
//
// It stays in cmd/hostveil for the reason theme.go does: the state directory
// is internal/history's, and the layering test forbids a UI package from
// importing it.

// layoutEnv names the arrangement when no --layout flag is given, for shells
// and systemd units that would rather set it once than repeat a flag. It is
// the counterpart of HOSTVEIL_THEME and HOSTVEIL_GLYPHS and resolves the same
// way — and it is declared here, beside them, rather than in the package that
// owns the registry, because the variable is part of the command line's
// interface and because both env-var harvests read cmd/hostveil.
const layoutEnv = "HOSTVEIL_LAYOUT"

// resolveLayout applies --layout > HOSTVEIL_LAYOUT > the remembered choice >
// the shipped arrangement.
func resolveLayout(flagValue string) (tui.Layout, error) {
	return tui.ResolveLayout(flagValue, os.Getenv(layoutEnv), stateDir())
}

// saveLayoutPref records the picker's choice in the state directory.
func saveLayoutPref(id string) error { return tui.SaveLayoutPref(stateDir(), id) }
