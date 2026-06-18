// hostveil is the single static binary that runs the CLI, the TUI,
// and the web server (depending on the subcommand). See plan.md and
// contracts/cli.md for the public surface.
package main

import (
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/cli"
	"github.com/seolcu/hostveil/internal/log"
	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/version"
)

func main() {
	// Pre-flight: refuse to start on non-Linux (FR-022). The check is
	// cheap and runs before any logging, so the user sees a clear
	// "unsupported platform" message even when the rest of main
	// would have failed noisily.
	if _, err := platform.Detect(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil:", err)
		os.Exit(cli.ExitError)
	}

	// Resolve XDG paths. We do this even on subcommands that don't
	// need the state.db (e.g. `version`) so the user sees a clear
	// error if their $HOME is unwritable.
	paths, err := resolvePaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: cannot resolve XDG paths:", err)
		os.Exit(cli.ExitError)
	}
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintln(os.Stderr, "hostveil: cannot create XDG directories:", err)
		os.Exit(cli.ExitError)
	}

	// Bootstrap a JSON structured logger; subcommands can replace it
	// with a context-bound instance (see internal/log).
	logger := log.New(os.Stderr, "main")
	_ = logger // reserved for the v3.0.0 implementation

	// Special case: `hostveil version` runs without a state.db
	// dependency. We detect it cheaply so the no-domain-code path
	// still works.
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(version.String())
		return
	}

	code := cli.Execute()
	os.Exit(code)
}
