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

// buildK3sSecretsEncryption runs k3s's own procedure for an existing
// cluster. Writing `secrets-encryption: true` and restarting — what this did
// in 3.33.0 — encrypts nothing on a cluster that already exists, and the
// checker, reading the same setting, called it fixed; a real cluster showed
// both (scripts/e2e/individual.sh). The documented sequence is enable, restart
// with the setting, rotate the keys so existing Secrets are rewritten, and
// restart again.
//
// It is Irreversible: once the rotation has rewritten Secrets encrypted,
// removing the setting and restarting leaves them unreadable, so there is no
// rollback, and a step that fails is reported where it stopped instead of
// being undone.
func buildK3sSecretsEncryption(f model.Finding) (Fix, error) {
	fx, err := k3sDropIn(f, "99-hostveil-secrets-encryption.yaml",
		"# Written by hostveil: encrypt Secrets at rest.\nsecrets-encryption: true\n",
		"Encrypt Kubernetes Secrets at rest",
		"Every Secret in the datastore is encrypted, the ones already there included, so a copied "+
			"/var/lib/rancher/k3s or a shipped snapshot no longer hands over every password the cluster holds.",
		"")
	if err != nil {
		return Fix{}, err
	}
	restart := fx.Actions[0].AfterWrite[0]
	a := &fx.Actions[0]
	a.Label = "Write " + a.Path + ", enable encryption, rotate the keys, and restart k3s"
	a.AfterWrite = [][]string{
		{"k3s", "secrets-encrypt", "enable"},
		restart,
		{"k3s", "secrets-encrypt", "rotate-keys"},
		restart,
	}
	a.Irreversible = true
	// Set whole rather than through k3sDropIn's: that one ends by promising
	// to remove the file if k3s will not start, which this fix does not do.
	a.Warning = "This cannot be rolled back: once Secrets are rewritten encrypted, removing the setting leaves " +
		"them unreadable, so the way back is `k3s secrets-encrypt disable` and a rotation, by hand. It restarts " +
		"k3s twice, which makes the API unavailable for the seconds each takes, and rewrites every Secret; " +
		"running pods keep running. If a step fails, Hostveil stops there and says which, rather than undoing " +
		"the earlier ones."
	return fx, nil
}
