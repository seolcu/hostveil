package main

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// withDomains holds the opt-in domains --with named for this invocation.
// buildEngine hands it to the engine, so every command that scans honours it
// without its own plumbing.
var withDomains []model.Source

// addWithFlag registers --with on a command that scans.
//
// A flag on each command, because sudo's
// env_reset would drop the variable on the re-exec (see elevate.go), and
// because "no config file" rules out remembering the choice anywhere else.
func addWithFlag(fs *flag.FlagSet) {
	fs.Func("with", "also run these opt-in domains (comma-separated: "+optInNames()+")", func(v string) error {
		srcs, err := parseOptIn(v)
		if err != nil {
			return err
		}
		for _, s := range srcs {
			if !slices.Contains(withDomains, s) {
				withDomains = append(withDomains, s)
			}
		}
		return nil
	})
}

// parseOptIn resolves a comma-separated list of opt-in domain names.
func parseOptIn(list string) ([]model.Source, error) {
	var out []model.Source
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		src, ok := model.ParseSource(name)
		if !ok || !src.OptIn() {
			return nil, fmt.Errorf("%q is not an opt-in domain (opt-in: %s)", name, optInNames())
		}
		out = append(out, src)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no domains named")
	}
	return out, nil
}

func optInNames() string {
	var names []string
	for _, s := range model.OptInSources() {
		names = append(names, s.String())
	}
	return strings.Join(names, ", ")
}
