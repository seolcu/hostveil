package fix

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/seolcu/hostveil/internal/model"
)

func registerPorts(r *Registry) {
	r.Register("ports.redis-bind", buildRedisDirective("bind", "bind 127.0.0.1 ::1", "Bind Redis to loopback",
		"Redis ships with no authentication by default; binding it to loopback means the only way to "+
			"reach it is already being on this host — closes it to the network entirely."))
	r.Register("ports.redis-protected-mode", buildRedisDirective("protected-mode", "protected-mode yes", "Enable Redis protected mode",
		"Turns on Redis's own built-in refusal to serve remote clients when no password is set — a "+
			"second, independent barrier behind the bind address, so a firewall or compose slip elsewhere "+
			"doesn't leave Redis exposed anyway."))
	r.Register("ports.redis-disable-config", buildRedisDirective("rename-command CONFIG", `rename-command CONFIG ""`, "Disable the Redis CONFIG command",
		"Removes remote CONFIG SET/GET, closing the well-known Redis-to-remote-code-execution chain "+
			"that writes a webshell or SSH key to disk via CONFIG SET dir/dbfilename."))
}

func buildRedisDirective(key, line, label, benefit string) Builder {
	return func(f model.Finding) (Fix, error) {
		path := f.Evidence["config"]
		if path == "" {
			return Fix{}, fmt.Errorf("finding %s names no Redis config", f.ID)
		}
		return Fix{Label: label, Kind: model.RemediationAuto, Actions: []Action{{Label: label, Benefit: benefit, Warning: "Restarting Redis can interrupt clients; validate this setting first.", Kind: ActionEdit, Path: path, TakesEffectOn: "a Redis restart", Transform: func(in []byte) ([]byte, error) {
			re := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(key) + `\s+.*$`)
			if re.Match(in) {
				return re.ReplaceAll(in, []byte(line)), nil
			}
			out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
			return append(out, []byte("\n"+line+"\n")...), nil
		}}}}, nil
	}
}
