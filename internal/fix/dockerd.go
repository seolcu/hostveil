package fix

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/seolcu/hostveil/internal/model"
)

// registerDockerd wires the Docker daemon findings. Every one of them was
// declined because the daemon reads its configuration once, at start: an
// edit to daemon.json changed nothing until a restart that stops every
// container on the host. AfterWrite is the answer to that — the restart is
// part of the action, and a daemon that refuses the new file gets the old one
// back — so each of these is now a fix that is in force when it reports
// success. They are all IndividualOnly: restarting Docker is the operator's
// outage to schedule, not a batch's.
func registerDockerd(r *Registry) {
	r.Register("dockerd.no-new-privileges", buildDockerdNoNewPrivileges)
	r.Register("dockerd.userns-remap", buildDockerdUsernsRemap)
	r.Register("dockerd.live-restore", buildDockerdLiveRestore)
	r.Register("dockerd.api-unauthenticated", buildDockerdRemoveTCP)
	r.Register("dockerd.api-tls-unverified", buildDockerdRequireClientCerts)
	r.Register("dockerd.socket-world-writable", buildDockerdSocketMode)
	r.Register("dockerd.group-members", buildDockerdRemoveGroupMember)
}

// dockerdValidate is `dockerd --validate`, Docker 23's own check of a config
// file. Older daemons do not have it, fail it on the original file as well,
// and runEditValidator's control run then sets it aside rather than letting
// it block a good edit.
var dockerdValidate = []string{"dockerd", "--validate", "--config-file", VerifyPathToken}

var restartDocker = [][]string{{"systemctl", "restart", "docker"}}

const dockerdRevertNote = "If the daemon refuses to start with the new file, Hostveil puts the old one back and starts it again. " +
	"The file edit has a checkpoint, and rolling it back restarts Docker under the original."

func daemonJSONPath(f model.Finding) (string, error) {
	p := f.Metadata["daemon_json"]
	if p == "" {
		return "", fmt.Errorf("finding %s does not say where daemon.json is", f.ID)
	}
	return p, nil
}

// daemonKeyEdit is an edit of one daemon.json key, created if the file does
// not exist yet (it does not, on most hosts).
func daemonKeyEdit(p, key, raw, label, benefit, warning string) Action {
	return Action{
		Label: label, Benefit: benefit, Warning: warning,
		Kind: ActionEdit, Path: p, CreateIfMissing: true,
		VerifyCmd: dockerdValidate,
		Transform: func(in []byte) ([]byte, error) { return setJSONKey(in, key, raw) },
	}
}

// daemonDefaultFix offers a daemon-wide default two ways: written and put in
// force by restarting Docker now, or written and left for the operator's own
// restart. The first is what fixes the finding; the second is for the host
// where now is the wrong time.
func daemonDefaultFix(f model.Finding, key, raw, label, benefit, risk string) (Fix, error) {
	p, err := daemonJSONPath(f)
	if err != nil {
		return Fix{}, err
	}
	setting := fmt.Sprintf("%q: %s", key, raw)
	now := daemonKeyEdit(p, key, raw, "Set "+setting+" in "+p+" and restart Docker now", benefit,
		risk+" Restarting Docker stops every container on the host and starts the ones with a restart policy again; "+
			"anything started by hand stays down. "+dockerdRevertNote)
	now.AfterWrite = restartDocker
	later := daemonKeyEdit(p, key, raw, "Set "+setting+" in "+p+"; restart Docker yourself later", benefit,
		risk+" Nothing changes until Docker restarts, and the finding is reported until then. "+
			"The file edit has a checkpoint.")
	later.TakesEffectOn = "`systemctl restart docker`"
	return Fix{
		Label: label, Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{now, later},
	}, nil
}

func buildDockerdNoNewPrivileges(f model.Finding) (Fix, error) {
	return daemonDefaultFix(f, "no-new-privileges", "true", "Make no-new-privileges the daemon default",
		"Every container started from now on runs with no-new-privileges, so a setuid binary inside one "+
			"can no longer turn a foothold in an application into root in its container.",
		"A container that relies on setuid escalation — sudo inside the container, an image whose entrypoint "+
			"switches users through a setuid helper — fails once recreated, and needs "+
			"`security_opt: [\"no-new-privileges:false\"]` to opt back out.")
}

func buildDockerdUsernsRemap(f model.Finding) (Fix, error) {
	return daemonDefaultFix(f, "userns-remap", `"default"`, "Turn on user-namespace remapping",
		"Root inside a container becomes an unprivileged UID on the host, so an escape or a careless "+
			"bind mount no longer lands as real root.",
		"This is the most disruptive daemon setting there is. Docker keeps remapped images and containers "+
			"in a separate storage directory, so every existing container and image disappears from "+
			"`docker ps -a` and `docker images` until it is turned off again, and pulls start from nothing. "+
			"Bind-mounted host files owned by root become unwritable to the remapped root. Containers using "+
			"privileged mode, host networking or host PID cannot run under it at all.")
}

func buildDockerdLiveRestore(f model.Finding) (Fix, error) {
	p, err := daemonJSONPath(f)
	if err != nil {
		return Fix{}, err
	}
	a := daemonKeyEdit(p, "live-restore", "true", `Set "live-restore": true in `+p+" and reload Docker",
		"Containers keep running while the daemon restarts, so upgrading Docker stops being an outage and "+
			"stops being the update that gets put off.",
		"Docker picks this setting up on a reload, so applying it stops nothing. It is unsupported in swarm "+
			"mode, and a daemon that cannot use it keeps running without it. If the daemon refuses the new "+
			"file, Hostveil puts the old one back and reloads again. Rolling it back restarts Docker, because "+
			"a reload does not turn the setting off again; with live-restore still on at that moment, the "+
			"containers keep running through it.")
	a.AfterWrite = [][]string{{"systemctl", "reload", "docker"}}
	// A reload applies the keys the file has and leaves the rest as they are,
	// so the rollback, which removes the key, needs a restart for the daemon
	// to drop it. Found by scripts/e2e/individual.sh on a real Docker.
	a.AfterRestore = restartDocker
	return Fix{Label: "Keep containers running across daemon restarts", Kind: model.RemediationReview,
		IndividualOnly: true, Actions: []Action{a}}, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, model.EvidenceSeparator)
}

// removeTCPAction takes the network endpoints off whichever source declared
// them. A finding whose endpoints come from both daemon.json and the unit
// cannot be one action — Docker refuses to start with hosts in both anyway,
// so a daemon that answered has them in one — and is declined.
func removeTCPAction(f model.Finding) (Action, error) {
	fileEPs, unitEPs := splitList(f.Metadata["file_endpoints"]), splitList(f.Metadata["unit_endpoints"])
	benefit := "Nothing on the network can reach the Docker API any more, which closes a port that is root on " +
		"this host for anyone who can connect to it."
	risk := "Anything that administers this daemon over TCP from another machine — a Portainer or Docker " +
		"context on your laptop, a CI runner, a remote agent — loses it. `DOCKER_HOST=ssh://user@host` is the " +
		"supported replacement and needs no open port. Restarting Docker stops every container and starts the " +
		"ones with a restart policy again. " + dockerdRevertNote
	switch {
	case len(fileEPs) > 0 && len(unitEPs) == 0:
		p, err := daemonJSONPath(f)
		if err != nil {
			return Action{}, err
		}
		var keep []string
		for _, h := range splitList(f.Metadata["file_hosts"]) {
			if !slices.Contains(fileEPs, h) {
				keep = append(keep, h)
			}
		}
		if len(keep) == 0 {
			// An empty list is not "the default": it is no socket at all.
			keep = []string{"unix:///var/run/docker.sock"}
		}
		raw, _ := json.Marshal(keep)
		a := daemonKeyEdit(p, "hosts", string(raw), "Remove "+strings.Join(fileEPs, ", ")+" from hosts in "+p+" and restart Docker",
			benefit, risk)
		a.AfterWrite = restartDocker
		return a, nil
	case len(unitEPs) > 0 && len(fileEPs) == 0:
		return unitWithoutEndpoints(f, unitEPs, benefit, risk)
	default:
		return Action{}, fmt.Errorf("finding %s: the endpoints are declared in both daemon.json and the unit, so no single edit removes them", f.ID)
	}
}

// unitWithoutEndpoints overrides the unit's ExecStart with the same argv
// minus the TCP -H flags, in a drop-in sorted after the packaged ones.
func unitWithoutEndpoints(f model.Finding, eps []string, benefit, risk string) (Action, error) {
	unit, argv := f.Metadata["unit"], f.Metadata["execstart"]
	if unit == "" || argv == "" {
		return Action{}, fmt.Errorf("finding %s: the unit has more than one ExecStart, or none was read, so there is no single command line to rewrite", f.ID)
	}
	if strings.ContainsAny(argv, "\"'\\$%") {
		return Action{}, fmt.Errorf("finding %s: the unit's command line carries quoting or specifiers this fix will not re-render", f.ID)
	}
	var kept []string
	fields := strings.Fields(argv)
	for i := 0; i < len(fields); i++ {
		name, val, attached := strings.Cut(fields[i], "=")
		if name == "-H" || name == "--host" {
			if !attached && i+1 < len(fields) {
				i++
				val = fields[i]
			}
			if slices.Contains(eps, val) {
				continue
			}
			kept = append(kept, name, val)
			continue
		}
		kept = append(kept, fields[i])
	}
	dropin := path.Join("/etc/systemd/system", unit+".d", "99-hostveil-api.conf")
	content := "[Service]\nExecStart=\nExecStart=" + strings.Join(kept, " ") + "\n"
	return Action{
		Label:   "Override " + unit + "'s ExecStart without " + strings.Join(eps, ", ") + ", then restart it",
		Benefit: benefit,
		Warning: risk + " The override is a new drop-in, " + dropin + "; rolling back deletes it.",
		Kind:    ActionEdit, Path: dropin, CreateIfMissing: true,
		Transform: func(in []byte) ([]byte, error) {
			if len(in) > 0 && string(in) != content {
				return nil, fmt.Errorf("%s already exists with other content", dropin)
			}
			return []byte(content), nil
		},
		AfterWrite: [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "restart", unit}},
	}, nil
}

func buildDockerdRemoveTCP(f model.Finding) (Fix, error) {
	a, err := removeTCPAction(f)
	if err != nil {
		return Fix{}, err
	}
	return Fix{Label: "Take the Docker API off the network", Kind: model.RemediationReview,
		IndividualOnly: true, Actions: []Action{a}}, nil
}

// buildDockerdRequireClientCerts offers both answers to a TLS socket that
// does not verify clients: remove it, or make it verify. The second is only
// possible from daemon.json, and only works if a CA is configured, which the
// daemon's own refusal to start will say — and the revert will undo.
func buildDockerdRequireClientCerts(f model.Finding) (Fix, error) {
	var actions []Action
	if f.Metadata["unit_endpoints"] == "" && f.Metadata["daemon_json"] != "" {
		verify := daemonKeyEdit(f.Metadata["daemon_json"], "tlsverify", "true",
			`Set "tlsverify": true in `+f.Metadata["daemon_json"]+" and restart Docker",
			"The API keeps listening, but only clients holding a certificate your CA signed can use it, which "+
				"turns encryption into authentication.",
			"The daemon needs \"tlscacert\" naming the CA that signs your client certificates; without it Docker "+
				"refuses to start. Every client that connects today without a certificate is refused afterwards. "+
				"Restarting Docker stops every container and starts the ones with a restart policy again. "+dockerdRevertNote)
		verify.AfterWrite = restartDocker
		actions = append(actions, verify)
	}
	remove, err := removeTCPAction(f)
	if err == nil {
		actions = append(actions, remove)
	}
	if len(actions) == 0 {
		return Fix{}, err
	}
	return Fix{Label: "Require client certificates on the Docker API", Kind: model.RemediationReview,
		IndividualOnly: true, Actions: actions}, nil
}

// buildDockerdSocketMode fixes the mode twice: in a docker.socket drop-in, so
// it survives the next start, and on the live socket, so it is true now.
// Restarting docker.socket would stop the daemon with it, which is an outage
// this finding does not need.
func buildDockerdSocketMode(f model.Finding) (Fix, error) {
	sock := f.Evidence["path"]
	if sock == "" {
		return Fix{}, fmt.Errorf("finding %s names no socket", f.ID)
	}
	dropin := "/etc/systemd/system/docker.socket.d/99-hostveil.conf"
	return Fix{Label: "Make the Docker socket group-only", Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{{
			Label: "Set SocketMode=0660 in " + dropin + " and chmod the live socket",
			Benefit: "Only root and the socket's group can reach the Docker API, so an ordinary account or a " +
				"compromised service on this host can no longer become root through it.",
			Warning: "Any account or service that reached Docker only because the socket was world-writable — " +
				"not through the group — loses access now. Add it to the group if it should keep it. The drop-in " +
				"is a new file with a checkpoint; rolling back deletes it, but the live socket keeps mode 0660 " +
				"until Docker next recreates it.",
			Kind: ActionEdit, Path: dropin, CreateIfMissing: true,
			Transform: func(in []byte) ([]byte, error) {
				const content = "[Socket]\nSocketMode=0660\n"
				if len(in) > 0 && string(in) != content {
					return nil, fmt.Errorf("%s already exists with other content", dropin)
				}
				return []byte(content), nil
			},
			AfterWrite: [][]string{{"systemctl", "daemon-reload"}, {"chmod", "0660", sock}},
		}}}, nil
}

func buildDockerdRemoveGroupMember(f model.Finding) (Fix, error) {
	group := f.Evidence["group"]
	member, _, _ := strings.Cut(f.Evidence["members"], model.EvidenceSeparator)
	if group == "" || member == "" {
		return Fix{}, fmt.Errorf("finding %s names no group member", f.ID)
	}
	return Fix{Label: "Remove " + member + " from the " + group + " group", Kind: model.RemediationReview,
		IndividualOnly: true, Actions: []Action{{
			Label: "Remove " + member + " from " + group + " (`gpasswd -d`)",
			Benefit: member + " can no longer become root on this host through the Docker API, which takes a " +
				"password-free, unlogged root grant away from an account that may not need it.",
			Warning: "If " + member + " is how you administer containers, `docker` stops working for it without " +
				"sudo; if it is a service — Portainer's agent, Watchtower, a CI runner — that service stops being " +
				"able to manage containers. Do not remove the account you are using right now until you have " +
				"another route in. Existing sessions keep the group until they log out. There is no checkpoint: " +
				"to reverse it, `usermod -aG " + group + " " + member + "`.",
			Kind:     ActionExec,
			Commands: [][]string{{"gpasswd", "-d", member, group}},
		}}}, nil
}
