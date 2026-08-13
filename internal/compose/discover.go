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
	return parseDiscovery(ctx, r, out)
}

type dockerProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func parseDiscovery(ctx context.Context, r platform.CommandRunner, out []byte) ([]Project, []string, error) {
	var entries []dockerProject
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, nil, err
	}
	var projects []Project
	var skipped []string
	for _, e := range entries {
		files := configFiles(e.ConfigFiles)
		if len(files) == 0 {
			// docker knows the project but names no config file for it, so
			// there is nothing to audit and nothing we failed to read either.
			continue
		}
		proj, err := effectiveProject(ctx, r, files)
		if err != nil {
			skipped = append(skipped, files[0])
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

// effectiveProject returns the project as docker composes it, not as any one
// of its files declares it.
//
// hostveil used to read the *first* path out of ConfigFiles and audit that.
// That is not a partial view of a layered project, it is a wrong one, and in
// the dangerous direction. `docker compose up` reads
// docker-compose.override.yml with no flag asked for, and `-f base.yml -f
// prod.yml` is the standard production pattern — so several files is the
// ordinary case, not an exotic one. Compose *appends* port mappings rather
// than replacing them, which docker shows plainly for a base binding redis to
// loopback and an override publishing it:
//
//	ports:
//	  - {host_ip: 127.0.0.1, target: 6379, published: "6379"}
//	  - {target: 6379, published: "6379"}
//
// Effective state: published on every interface. Reading the base file alone
// sees the loopback binding, finds nothing, and reports an exposed datastore
// as clean.
//
// So the merge is asked of the tool that owns it. This is the same move as
// reading kernel parameters through the file systemd-sysctl will actually
// apply and unit properties through `systemctl show` — a checker that
// re-implements somebody else's precedence rules is a checker that will
// disagree with reality on the hosts that matter.
//
// `config` also interpolates, so a `${REDIS_PORT}:6379` mapping resolves the
// way it will at run time instead of parsing as a literal.
func effectiveProject(ctx context.Context, r platform.CommandRunner, files []string) (Project, error) {
	argv := make([]string, 0, len(files)*2+2)
	argv = append(argv, "compose")
	for _, f := range files {
		argv = append(argv, "-f", f)
	}
	argv = append(argv, "config")

	merged, err := r.Run(ctx, "docker", argv...)
	if err == nil {
		proj, perr := Parse(files[0], merged)
		// Every file, not just the one the merged content is labelled with.
		// The label answers "what is this project called"; the list answers
		// "which file decides this setting", and only the second is a
		// question a fix can act on.
		proj.Files = files
		return proj, perr
	}

	// docker would not answer: an unset variable a mapping demands, a file it
	// cannot read, a compose version too old for the flags. With one file
	// there is no merge to lose — that file *is* the project, modulo
	// interpolation — so fall back to reading it and keep auditing. With
	// several, the merge is the whole question and guessing at it would put
	// back the wrong answer this exists to remove; the caller reports it as
	// ground not covered instead.
	if len(files) == 1 {
		proj, perr := ParseFile(files[0])
		proj.Files = files
		return proj, perr
	}
	return Project{}, fmt.Errorf("cannot resolve the merged configuration of %s: %w",
		strings.Join(files, ", "), err)
}

// configFiles splits docker's comma-separated ConfigFiles field, in the order
// docker reports it — which is the order compose merged them in, and the
// order `-f` has to repeat for the merge to come out the same.
func configFiles(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
