package fix

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
)

// registerCompose wires the compose-domain fixes into the registry.
func registerCompose(r *Registry) {
	r.Register("compose.ds006", buildAddNoNewPrivileges)
	r.Register("compose.ds008", buildAddRestart)
	r.Register("compose.ds010", buildSetMemLimit)
	r.Register("compose.ds018", buildBindLoopback)
	r.Register("compose.ds019", buildBindLoopback)
	r.Register("compose.dr002", buildBindLoopback)
	// Registered by exact ID, never as "cve.*": the glob would sweep up
	// every per-CVE finding, which the registry declines on purpose.
	r.Register("cve.outdated-image", buildRepullImage)
}

// composeEdit builds an edit action whose Transform loads the compose file,
// applies mutate in memory, and renders it back — pure, so preview and
// apply share it.
func composeEdit(path, label, warning string, mutate func(*compose.Doc) error) Action {
	return Action{
		Label:   label,
		Warning: warning,
		Kind:    ActionEdit,
		Path:    path,
		Transform: func(in []byte) ([]byte, error) {
			doc, err := compose.Load(in)
			if err != nil {
				return nil, err
			}
			if err := mutate(doc); err != nil {
				return nil, err
			}
			return doc.Bytes()
		},
	}
}

// composeFiles is every config file the project is composed from, in the
// order docker applies them.
//
// The older "file" key is the first of those, kept because it names the
// project in a message. It was also what every builder edited, which is the
// bug this list exists to close: on a layered project the merged state is what
// docker runs, and the first file is not necessarily the one that decides
// anything.
func composeFiles(f model.Finding) ([]string, error) {
	if list := f.Metadata["files"]; list != "" {
		return strings.Split(list, model.PathListSeparator), nil
	}
	if path := f.Metadata["file"]; path != "" {
		return []string{path}, nil
	}
	return nil, fmt.Errorf("finding %s has no compose file path", f.ID)
}

// composeScalarTarget is the file to edit when adding or replacing a scalar
// key — security_opt, restart, mem_limit.
//
// Compose resolves scalars last-wins, so the file that decides is the last one
// defining the service. Writing into an earlier one would be overwritten by
// the merge and the fix would report a success docker never sees.
func composeScalarTarget(f model.Finding) (string, error) {
	files, err := composeFiles(f)
	if err != nil {
		return "", err
	}
	if len(files) == 1 {
		return files[0], nil
	}
	for i := len(files) - 1; i >= 0; i-- {
		proj, err := compose.ParseFile(files[i])
		if err != nil {
			continue // a file this scan could not read decides nothing it can prove
		}
		if _, ok := proj.Services[f.Service]; ok {
			return files[i], nil
		}
	}
	return "", fmt.Errorf("finding %s: none of the %d files this project is composed from defines %s, so there is no file to edit",
		f.ID, len(files), f.Service)
}

// composePortTarget is the file to edit when rebinding a published port, and
// it is a different question from the scalar one because compose *appends*
// port mappings rather than replacing them. A wide binding in any one file
// exposes the service however the others bind it, so rewriting one file while
// another still publishes 0.0.0.0 changes nothing docker will do.
//
// One file publishing it wide: that is the file, and on the common layout —
// a base binding to loopback and an override republishing it — this is the
// override, which is precisely the file the old code did not edit.
//
// Several: hostveil declines. It is the same answer persistSysctl gives when
// the file it would write is outranked. A fix that cannot name the deciding
// file has not got one, and editing the first and reporting success is worse
// than saying so.
func composePortTarget(f model.Finding, port string) (string, error) {
	files, err := composeFiles(f)
	if err != nil {
		return "", err
	}
	if len(files) == 1 {
		return files[0], nil
	}
	var publishes []string
	for _, path := range files {
		proj, err := compose.ParseFile(path)
		if err != nil {
			continue
		}
		svc, ok := proj.Services[f.Service]
		if !ok {
			continue
		}
		for _, p := range svc.Ports {
			if p.HostPort == port && p.ExposedOnAllInterfaces() {
				publishes = append(publishes, path)
				break
			}
		}
	}
	switch len(publishes) {
	case 1:
		return publishes[0], nil
	case 0:
		return "", fmt.Errorf("finding %s: port %s is published by the merge of %d files and by none of them alone, so hostveil cannot tell which one decides it",
			f.ID, port, len(files))
	default:
		return "", fmt.Errorf("finding %s: port %s is published on every interface by %s, and compose appends port mappings rather than replacing them — rewriting one would leave the others binding 0.0.0.0",
			f.ID, port, strings.Join(publishes, " and "))
	}
}

func buildAddNoNewPrivileges(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	return Fix{
		Label: "Add no-new-privileges to " + svc,
		Kind:  model.RemediationAuto,
		Actions: []Action{composeEdit(path, "Add security_opt no-new-privileges:true", "",
			func(d *compose.Doc) error { return d.AddSecurityOpt(svc, "no-new-privileges:true") })},
	}, nil
}

func buildAddRestart(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	return Fix{
		Label: "Set restart policy for " + svc,
		Kind:  model.RemediationAuto,
		Actions: []Action{composeEdit(path, "Set restart: unless-stopped", "",
			func(d *compose.Doc) error { return d.SetScalar(svc, "restart", "unless-stopped") })},
	}, nil
}

// memLimits are the alternatives offered for ds010. hostveil cannot know
// what a service actually uses, so it offers defensible starting points and
// lets the user pick rather than inventing a number.
var memLimits = []struct{ value, kind string }{
	{"512m", "small service (proxy, exporter, static site)"},
	{"1g", "typical application container"},
	{"2g", "database or JVM service"},
}

func buildSetMemLimit(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	warning := "Too low a limit gets the container OOM-killed under load. Start generous, watch `docker stats`, and tighten later. This is a file edit, so it is fully reversible."
	actions := make([]Action, 0, len(memLimits))
	for _, m := range memLimits {
		actions = append(actions, composeEdit(path,
			fmt.Sprintf("Limit %s to %s — %s", svc, m.value, m.kind), warning,
			func(d *compose.Doc) error { return d.SetScalar(svc, "mem_limit", m.value) }))
	}
	return Fix{
		Label:   "Set a memory limit for " + svc,
		Kind:    model.RemediationReview,
		Actions: actions,
	}, nil
}

// buildRepullImage remediates the per-image CVE rollup by re-pulling the
// image the service already asked for.
//
// It refuses digest-pinned references. The checker declares those Manual
// too, so the rule is encoded at both ends and Engine.classify takes the
// stricter — neither side alone can produce a fix button that leads
// nowhere. Keep both: for a while classify did not take the stricter when
// the checker's side was Manual, and this refusal was the only thing
// holding the promise.
//
// applyExec runs argv with no shell and no working directory, so the
// compose file must be named explicitly with -f. That also sets the project
// directory to the file's parent, keeping relative env_file and build paths
// resolvable.
func buildRepullImage(f model.Finding) (Fix, error) {
	path, err := composeScalarTarget(f)
	if err != nil {
		return Fix{}, err
	}
	// The bare service name, not f.Service: CVE image findings qualify the
	// service with its compose project to keep two projects' same-named
	// services distinct in Finding.Key(), and `docker compose -f <file>` wants
	// the name as written in that file.
	svc := f.Metadata["service"]
	if svc == "" {
		return Fix{}, fmt.Errorf("finding %s has no service to update", f.ID)
	}
	if f.Evidence["reference"] == "digest" {
		return Fix{}, fmt.Errorf("finding %s pins its image by digest; pulling cannot change it", f.ID)
	}

	noRollback := "There is no rollback checkpoint: exec fixes are not file-backed, so hostveil cannot undo this."
	pull := []string{"docker", "compose", "-f", path, "pull", svc}

	return Fix{
		Label: "Update the image for " + svc,
		Kind:  model.RemediationReview,
		Actions: []Action{
			{
				Label:   "Pull the new image and recreate " + svc + " now",
				Warning: "This recreates the container: the service goes down briefly and comes back on a different image. " + noRollback + " Note the current image ID (`docker compose -f " + path + " images`) before applying, so you can pin it back if the new one misbehaves.",
				Kind:    ActionExec,
				Commands: [][]string{
					pull,
					{"docker", "compose", "-f", path, "up", "-d", svc},
				},
			},
			{
				Label:    "Download the new image only; recreate " + svc + " on your own schedule",
				Warning:  "This changes nothing that is running: the image is downloaded but the container keeps using the old one until you recreate it, and the finding will still be reported until then. " + noRollback,
				Kind:     ActionExec,
				Commands: [][]string{pull},
			},
		},
	}, nil
}

func buildBindLoopback(f model.Finding) (Fix, error) {
	hostPort := f.Evidence["port"]
	if hostPort == "" {
		return Fix{}, fmt.Errorf("finding %s has no host port to rebind", f.ID)
	}
	path, err := composePortTarget(f, hostPort)
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	warning := "After this, the service is reachable only from this host. If you access it from another machine, use an SSH tunnel, VPN, or reverse proxy."
	return Fix{
		Label: fmt.Sprintf("Bind %s port %s to localhost", svc, hostPort),
		Kind:  model.RemediationAuto,
		Actions: []Action{composeEdit(path, "Bind published port to 127.0.0.1", warning,
			func(d *compose.Doc) error { return d.BindPortLoopback(svc, hostPort) })},
	}, nil
}
