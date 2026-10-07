package fix

import (
	"fmt"
	"path"

	"github.com/seolcu/hostveil/internal/model"
)

func registerKube(r *Registry) {
	r.Register("kube.anonymous-auth", buildK3sAnonymousOff)
	r.Register("kube.secrets-unencrypted", buildK3sSecretsEncryption)
}

// k3sDropIn writes one hostveil-owned file in config.yaml.d and restarts k3s
// to read it. The checker offers these only where no command-line flag
// outranks the file, and resolves k3s's own order to say so.
func k3sDropIn(f model.Finding, name, content, label, benefit, warning string) (Fix, error) {
	dir := f.Metadata["k3s_dropin_dir"]
	if dir == "" {
		return Fix{}, fmt.Errorf("finding %s is not on a k3s host whose files decide the setting", f.ID)
	}
	restart := [][]string{{"systemctl", "restart", "k3s"}}
	if f.Metadata["k3s_restart"] == "openrc" {
		restart = [][]string{{"rc-service", "k3s", "restart"}}
	}
	p := path.Join(dir, name)
	return Fix{Label: label, Kind: model.RemediationReview, IndividualOnly: true, Actions: []Action{{
		Label:   "Write " + p + " and restart k3s",
		Benefit: benefit,
		Warning: warning + " Restarting k3s makes the API unavailable for the seconds it takes to start; running " +
			"pods keep running. If k3s will not start with the new file, Hostveil removes it and starts k3s again.",
		Kind: ActionEdit, Path: p, CreateIfMissing: true,
		Transform: func(in []byte) ([]byte, error) {
			if len(in) > 0 && string(in) != content {
				return nil, fmt.Errorf("%s already exists with other content", p)
			}
			return []byte(content), nil
		},
		AfterWrite: restart,
	}}}, nil
}

func buildK3sAnonymousOff(f model.Finding) (Fix, error) {
	// `+` appends to what earlier files set, and the component takes a
	// repeated flag's last value — so this turns it off without touching the
	// file that turned it on.
	return k3sDropIn(f, "99-hostveil-anonymous-auth.yaml",
		"# Written by hostveil: turns off anonymous requests set earlier.\n"+
			"kube-apiserver-arg+:\n  - anonymous-auth=false\n"+
			"kubelet-arg+:\n  - anonymous-auth=false\n",
		"Refuse unauthenticated requests to Kubernetes",
		"Requests with no credential are refused instead of reaching RBAC as system:anonymous, so a stray "+
			"binding for anonymous users stops being the whole cluster.",
		"Anything that talks to the API server or the kubelet without credentials — a monitoring scrape, a "+
			"health check against a path other than /livez, /readyz or /healthz — starts getting 401s. The "+
			"drop-in is a new file with a checkpoint; rolling it back deletes it and restarts k3s.")
}

func buildK3sSecretsEncryption(f model.Finding) (Fix, error) {
	return k3sDropIn(f, "99-hostveil-secrets-encryption.yaml",
		"# Written by hostveil: encrypt Secrets at rest.\nsecrets-encryption: true\n",
		"Encrypt Kubernetes Secrets at rest",
		"Secrets written from now on are encrypted in the datastore, so a copied /var/lib/rancher/k3s or "+
			"a shipped snapshot no longer hands over every password the cluster holds.",
		"Secrets written before this stay unencrypted until they are rewritten: run `k3s secrets-encrypt "+
			"rotate-keys` once k3s is back. Do not roll this back once Secrets have been written encrypted — "+
			"switching encryption off that way leaves them unreadable; use `k3s secrets-encrypt disable` and "+
			"re-encrypt instead. The drop-in is a new file with a checkpoint.")
}
