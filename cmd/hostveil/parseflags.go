package main

import (
	"errors"
	"flag"
)

// parseFlags parses a subcommand's flags and reports the exit code to return,
// or -1 to carry on.
//
// -h/--help is not an error. Go's flag package reports it as flag.ErrHelp
// after printing usage, and treating that like a parse failure made every
// `hostveil <cmd> --help` exit 2. The top-level case was fixed in #520; the
// same bug survived one level down in all four subcommands.
func parseFlags(fs *flag.FlagSet, args []string) int {
	err := fs.Parse(args)
	switch {
	case err == nil:
		return -1
	case errors.Is(err, flag.ErrHelp):
		return 0
	default:
		return 2 // flag already printed the error and the usage
	}
}
