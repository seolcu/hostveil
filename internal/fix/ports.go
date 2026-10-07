package fix

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/seolcu/hostveil/internal/model"
)

func registerPorts(r *Registry) {
	r.Register("ports.exposed-datastore", buildUFWDenyPort)
	r.Register("ports.exposed-admin", buildUFWDenyPort)
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

// buildUFWDenyPort closes one exposed port with a ufw rule placed ahead of
// every other, so an earlier allow cannot win. It is the remediation that
// fits all seventeen products on the ports lists at once; binding each to
// loopback is a different file and syntax per product, and the finding
// carries none of them.
//
// The checker offers it only where ufw is running and the port is not
// Docker's, and reads ufw's rules back the same way ufw applies them — so the
// re-check sees the port closed.
func buildUFWDenyPort(f model.Finding) (Fix, error) {
	port := f.Evidence["port"]
	if port == "" {
		return Fix{}, fmt.Errorf("finding %s names no port", f.ID)
	}
	rule := port + "/tcp"
	// The allow goes first. ufw treats a deny with the same match as an
	// allow already in the ruleset as a duplicate — "Skipping inserting
	// existing rule", exit 0 — so prepending alone did nothing on exactly the
	// host this finding fires on, one with that port allowed, while the fix
	// reported success. Found on a real ufw by scripts/e2e/individual.sh.
	// Deleting a rule that is not there is also exit 0, and prepend works on
	// an empty ruleset, so the pair is safe whatever the ruleset held.
	cmds := [][]string{{"ufw", "delete", "allow", rule}, {"ufw", "prepend", "deny", rule}}
	what := f.Service
	if what == "" {
		what = "port " + port
	}
	return Fix{Label: "Close " + rule + " to the network with ufw", Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{{
			Label: "Deny " + rule + " ahead of every other ufw rule",
			Benefit: what + " stops being reachable from any other machine, while everything on this host keeps " +
				"reaching it as before.",
			Warning: "Every remote client of " + what + " is cut off — an application server on another machine, a " +
				"replica, a backup job, your own desktop client — including ones a subnet allow rule used to let " +
				"in. An existing `allow " + rule + "` is deleted first, because ufw will not put a deny for the same " +
				"port ahead of it. There is no checkpoint: undo it with `ufw delete deny " + rule + "`, and " +
				"`ufw allow " + rule + "` if you had that rule. Binding the service to 127.0.0.1 in its own " +
				"configuration is the cleaner long-term fix.",
			Kind:     ActionExec,
			Commands: cmds,
		}}}, nil
}
