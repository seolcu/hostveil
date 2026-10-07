package fix

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

func registerNetworkRisky(r *Registry) {
	r.Register("firewall.docker-bypass", buildUFWDocker)
	r.Register("compose.dr004", buildTightenEnvFiles)
	r.Register("kube.token-readable", buildTightenKubeToken)
	r.Register("kube.kubeconfig-readable", buildTightenKubeconfig)
}

// ufwAfterRules is where ufw reads rules applied after its own, and the
// DOCKER-USER chain is the one Docker promises never to touch: rules there
// run before Docker's own accept for a published port.
const ufwAfterRules = "/etc/ufw/after.rules"

const ufwDockerBegin = "# BEGIN UFW AND DOCKER"

// ufwDockerBlock is the ufw-docker project's after.rules block. It sends
// forwarded traffic through ufw's own forward chain, lets the private ranges
// through, and drops new connections from anywhere else to a container — so
// a published port is reachable from outside only where a `ufw route allow`
// rule says so, which is what an operator reading `ufw status` already
// believed.
const ufwDockerBlock = ufwDockerBegin + `
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
`

func buildUFWDocker(f model.Finding) (Fix, error) {
	published := f.Evidence["published"]
	return Fix{
		Label: "Make ufw govern published container ports", Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{{
			Label: "Add the ufw-docker rules to " + ufwAfterRules + " and reload ufw",
			Benefit: "Published container ports stop bypassing the firewall: from outside the private ranges " +
				"they are reachable only where a `ufw route allow` rule says so, which is what `ufw status` " +
				"already claims.",
			Warning: "Every port a container publishes stops being reachable from the internet the moment ufw " +
				"reloads — " + published + " included — until you allow it with " +
				"`ufw route allow proto tcp from any to any port <container port>`. Traffic from 10/8, " +
				"172.16/12 and 192.168/16 is still let through. If ufw refuses the rules, Hostveil puts the " +
				"original file back and reloads again. The edit has a checkpoint, and rolling it back reloads ufw.",
			Kind: ActionEdit, Path: ufwAfterRules,
			Transform: func(in []byte) ([]byte, error) {
				if strings.Contains(string(in), ufwDockerBegin) {
					return nil, fmt.Errorf("%s already carries a ufw-docker block", ufwAfterRules)
				}
				out := string(in)
				if out != "" && !strings.HasSuffix(out, "\n") {
					out += "\n"
				}
				return []byte(out + "\n" + ufwDockerBlock), nil
			},
			AfterWrite: [][]string{{"ufw", "reload"}},
		}},
	}, nil
}

// buildTightenEnvFiles takes group and other access off a service's
// env_files. Docker Compose reads them as whoever runs it, and the container
// never does, so nothing that worked before stops working unless another
// account was running compose against this project.
func buildTightenEnvFiles(f model.Finding) (Fix, error) {
	files, err := composeFiles(f)
	if err != nil {
		return Fix{}, err
	}
	dir := filepath.Dir(files[0])
	var paths []string
	for _, p := range strings.Split(f.Evidence["env_files"], model.PathListSeparator) {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		paths = append(paths, filepath.Clean(p))
	}
	if len(paths) == 0 {
		return Fix{}, fmt.Errorf("finding %s names no env_file", f.ID)
	}
	// SafeRoot is the project directory when every file is under it, which is
	// the ordinary layout and the one where the account that owns the project
	// could otherwise swap a file for a symlink between scan and apply.
	safeRoot := dir
	for _, p := range paths {
		if rel, err := filepath.Rel(dir, p); err != nil || strings.HasPrefix(rel, "..") {
			safeRoot = ""
		}
	}
	return Fix{
		Label: "Make " + f.Service + "'s env_file readable only by its owner", Kind: model.RemediationReview,
		Actions: []Action{{
			Label: "Remove group and other access from " + strings.Join(paths, ", "),
			Benefit: "The credentials in the env_file stop being readable by every other account on the host, " +
				"which is the easiest way a secret leaks off a shared machine.",
			Warning: "Another account that runs `docker compose` against this project — a deploy user, a CI " +
				"runner — can no longer read the file and fails to start the service. Checking that the file is " +
				"out of git and off-host backups is still yours to do. The old mode is checkpointed.",
			Kind: ActionMode, Paths: paths, SafeRoot: safeRoot,
			Mode: func(cur fs.FileMode) fs.FileMode { return tighten(cur, 0o700) },
		}},
	}, nil
}

func buildTightenKubeToken(f model.Finding) (Fix, error) {
	p := f.Evidence["path"]
	if p == "" {
		return Fix{}, fmt.Errorf("finding %s names no token file", f.ID)
	}
	return Fix{
		Label: "Make the k3s join token readable only by root", Kind: model.RemediationReview,
		Actions: []Action{{
			Label: "chmod " + p + " to 0600",
			Benefit: "No local account can read the token any more, so none of them can hand the cluster to a " +
				"machine of their choosing from here on.",
			Warning: "It has already been readable, so anything that copied it can still join a node. Rotate it " +
				"after this (`k3s token rotate`), which hostveil does not do because it changes what every " +
				"joining node has to present. The old mode is checkpointed.",
			Kind: ActionMode, Paths: []string{p},
			Mode: func(cur fs.FileMode) fs.FileMode { return tighten(cur, 0o600) },
		}},
	}, nil
}

// k0sAdminConf is where k0s writes its admin kubeconfig. k0s writes it once,
// 0640, so a chmod back to that is durable; k3s rewrites its kubeconfig at
// every start from write-kubeconfig-mode, so a chmod there lasts until then.
const k0sAdminConf = "/var/lib/k0s/pki/admin.conf"

func buildTightenKubeconfig(f model.Finding) (Fix, error) {
	p := f.Evidence["path"]
	if p == "" {
		return Fix{}, fmt.Errorf("finding %s names no kubeconfig", f.ID)
	}
	mask, mode := fs.FileMode(0o600), "0600"
	durable := "k3s writes this file again at every start from its write-kubeconfig-mode setting, so this lasts " +
		"until k3s restarts. Make it permanent by setting `write-kubeconfig-mode: \"0600\"`"
	if setIn := f.Evidence["set-in"]; setIn != "" {
		durable += " where the current mode is set, " + setIn + "."
	} else {
		durable += " in /etc/rancher/k3s/config.yaml."
	}
	if p == k0sAdminConf {
		mask, mode = 0o640, "0640"
		durable = "k0s does not rewrite it, so this lasts."
	}
	return Fix{
		Label: "Stop every account reading the cluster-admin kubeconfig", Kind: model.RemediationReview,
		IndividualOnly: true,
		Actions: []Action{{
			Label: "chmod " + p + " to " + mode,
			Benefit: "Local accounts and services lose the cluster-admin credentials, and with them the " +
				"privileged pod that is root on this host.",
			Warning: "kubectl stops working for anyone who used this file without sudo — give them a " +
				"kubeconfig of their own. " + durable + " The old mode is checkpointed.",
			Kind: ActionMode, Paths: []string{p},
			Mode: func(cur fs.FileMode) fs.FileMode { return tighten(cur, mask) },
		}},
	}, nil
}
