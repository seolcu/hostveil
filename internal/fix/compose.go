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
	r.Register("compose.ds018", buildBindLoopback)
	r.Register("compose.ds019", buildBindLoopback)
	r.Register("compose.dr002", buildBindLoopback)
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
