package fix

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/seolcu/hostveil/internal/model"
)

func registerPorts(r *Registry) {
	r.Register("ports.redis-bind", buildRedisDirective("bind", "bind 127.0.0.1 ::1", "Bind Redis to loopback"))
	r.Register("ports.redis-protected-mode", buildRedisDirective("protected-mode", "protected-mode yes", "Enable Redis protected mode"))
	r.Register("ports.redis-disable-config", buildRedisDirective("rename-command CONFIG", `rename-command CONFIG ""`, "Disable the Redis CONFIG command"))
}

func buildRedisDirective(key, line, label string) Builder {
	return func(f model.Finding) (Fix, error) {
		path := f.Evidence["config"]
		if path == "" {
			return Fix{}, fmt.Errorf("finding %s names no Redis config", f.ID)
		}
		return Fix{Label: label, Kind: model.RemediationAuto, Actions: []Action{{Label: label, Warning: "Restarting Redis can interrupt clients; validate this setting first.", Kind: ActionEdit, Path: path, TakesEffectOn: "a Redis restart", Transform: func(in []byte) ([]byte, error) {
			re := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(key) + `\s+.*$`)
			if re.Match(in) {
				return re.ReplaceAll(in, []byte(line)), nil
			}
			out := append([]byte(nil), bytes.TrimRight(in, "\n")...)
			return append(out, []byte("\n"+line+"\n")...), nil
		}}}}, nil
	}
}
