package fix

import (
	"fmt"

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

func composeFilePath(f model.Finding) (string, error) {
	path := f.Metadata["file"]
	if path == "" {
		return "", fmt.Errorf("finding %s has no compose file path", f.ID)
	}
	return path, nil
}

func buildAddNoNewPrivileges(f model.Finding) (Fix, error) {
	path, err := composeFilePath(f)
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
	path, err := composeFilePath(f)
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
	path, err := composeFilePath(f)
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
// nowhere.
//
// applyExec runs argv with no shell and no working directory, so the
// compose file must be named explicitly with -f. That also sets the project
// directory to the file's parent, keeping relative env_file and build paths
// resolvable.
func buildRepullImage(f model.Finding) (Fix, error) {
	path, err := composeFilePath(f)
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
	path, err := composeFilePath(f)
	if err != nil {
		return Fix{}, err
	}
	hostPort := f.Evidence["port"]
	if hostPort == "" {
		return Fix{}, fmt.Errorf("finding %s has no host port to rebind", f.ID)
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
