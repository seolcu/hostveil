package compose

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// Discover lists the compose projects docker knows about via
// `docker compose ls --format json` and parses each project's config
// file. Projects that fail to parse are skipped rather than aborting the
// whole discovery.
func Discover(ctx context.Context, r platform.CommandRunner) ([]Project, error) {
	out, err := r.Run(ctx, "docker", "compose", "ls", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	return parseDiscovery(out)
}

type dockerProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func parseDiscovery(out []byte) ([]Project, error) {
	var entries []dockerProject
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, err
	}
	var projects []Project
	for _, e := range entries {
		path := firstConfigFile(e.ConfigFiles)
		if path == "" {
			continue
		}
		proj, err := ParseFile(path)
		if err != nil {
			continue // a single unreadable project must not fail discovery
		}
		if e.Name != "" {
			proj.Name = e.Name
		}
		projects = append(projects, proj)
	}
	return projects, nil
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
