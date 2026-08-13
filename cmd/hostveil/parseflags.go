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

// parseAndElevate is parseFlags followed by the re-exec under sudo, and is
// what every subcommand calls.
//
// The order is the point. Elevation used to happen in run(), before dispatch
// and therefore before any subcommand had looked at its arguments — so
// `hostveil --theme no-such-theme` asked for a password, took it, re-executed
// as root, and *then* exited 2 on a usage error. resolveCommand routes any
// leading flag to scan, which is root-benefiting, so a typo cost a password
// every time.
//
// Doing it here rather than at each call site keeps the two in one place, and
// fs.Name() is already the subcommand name needsRoot is keyed on. The two
// print-only commands never reach this, which is what keeps `version` and
// `help` from prompting.
//
// parseFlags stays separate so a test can exercise the parsing without a
// process that replaces itself; TestNoCommandParsesFlagsWithoutElevating holds
// the commands to this one.
func parseAndElevate(fs *flag.FlagSet, args []string) int {
	if code := parseFlags(fs, args); code >= 0 {
		return code
	}
	maybeElevate(fs.Name()) // on success the process is replaced and does not return
	return -1
}
