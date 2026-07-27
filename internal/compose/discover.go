package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// Discover lists the compose projects docker knows about via
// `docker compose ls --format json` and parses each project's config file.
//
// A project that fails to parse is skipped rather than aborting the whole
// discovery — one broken stack must not blind the checker to the other
// twelve. The paths of those projects are returned as the second value, and
// callers must not drop it: a skipped project is ground the scan did not
// cover, and reporting ScanDone over a subset is how "I couldn't look"
// becomes "nothing there". A compose file the scan cannot read, or one whose
// ports the typed model rejects, is enough to trigger it.
func Discover(ctx context.Context, r platform.CommandRunner) ([]Project, []string, error) {
	out, err := r.Run(ctx, "docker", "compose", "ls", "--all", "--format", "json")
	if err != nil {
		return nil, nil, fmt.Errorf("list compose projects: %w", err)
	}
	return parseDiscovery(out)
}

type dockerProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func parseDiscovery(out []byte) ([]Project, []string, error) {
	var entries []dockerProject
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, nil, err
	}
	var projects []Project
	var skipped []string
	for _, e := range entries {
		path := firstConfigFile(e.ConfigFiles)
		if path == "" {
			// docker knows the project but names no config file for it, so
			// there is nothing to audit and nothing we failed to read either.
			continue
		}
		proj, err := ParseFile(path)
		if err != nil {
			skipped = append(skipped, path)
			continue
		}
		if e.Name != "" {
			proj.Name = e.Name
		}
		projects = append(projects, proj)
	}
	sort.Strings(skipped) // stable evidence across runs
	return projects, skipped, nil
}

// firstConfigFile returns the first path from docker's comma-separated
// ConfigFiles field.
func firstConfigFile(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.IndexByte(s, ','); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
