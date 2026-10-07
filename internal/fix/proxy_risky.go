package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"gopkg.in/yaml.v3"
)

// registerProxyRisky wires the proxy findings that were declined because the
// right edit was unambiguous and the file, or the consequence, was not. Where
// the checker can name one file it now does, and these edit it and then put
// it in force: nginx and Caddy check the file themselves before the reload,
// and AfterWrite puts the old one back if either refuses.
func registerProxyRisky(r *Registry) {
	r.Register("proxy.tls-deprecated-protocols", buildNginxModernTLS)
	r.Register("proxy.directory-listing", buildNginxNoAutoindex)
	r.Register("proxy.traefik-api-insecure", buildTraefikSecureAPI)
	r.Register("proxy.admin-api-exposed", buildCaddyAdminLoopback)
}

// nginxReload validates the whole live configuration, which is the only way
// to validate an included fragment, and then reloads. A failure at either
// step brings the original file back.
//
// try-reload-or-restart rather than reload: on a host where nginx is installed
// and stopped, reload fails and the fix would be undone for nothing, while
// reload-or-restart would start a service somebody stopped. This reloads a
// running nginx and leaves a stopped one stopped, with the file fixed for when
// it starts.
var nginxReload = [][]string{{"nginx", "-t"}, {"systemctl", "try-reload-or-restart", "nginx"}}

const proxyRevertNote = "If the proxy refuses the new configuration, Hostveil puts the original file back and reloads again. " +
	"The edit has a checkpoint and rolls back exactly."

// singleConfig is the one file an nginx finding names. The checker marks a
// finding spread over several as Manual, so more than one here is a finding
// built by hand.
func singleConfig(f model.Finding) (string, error) {
	files := strings.Split(f.Evidence["config"], ", ")
	if len(files) != 1 || files[0] == "" {
		return "", fmt.Errorf("finding %s names %d configuration files; a fix edits exactly one", f.ID, len(files))
	}
	return files[0], nil
}

var sslProtocolsLine = regexp.MustCompile(`(?m)^([ \t]*)ssl_protocols[ \t][^;]*;`)

func buildNginxModernTLS(f model.Finding) (Fix, error) {
	p, err := singleConfig(f)
	if err != nil {
		return Fix{}, err
	}
	return Fix{Label: "Offer only TLS 1.2 and 1.3", Kind: model.RemediationReview, Actions: []Action{{
		Label: "Set every ssl_protocols in " + p + " to TLSv1.2 TLSv1.3, then reload nginx",
		Benefit: "Connections can no longer be negotiated down to TLS 1.0 or 1.1, which every current browser " +
			"already refuses, so nothing that can connect today loses anything.",
		Warning: "A client that only speaks TLS 1.0 or 1.1 — a very old Android or Java, an embedded device — stops " +
			"connecting. " + proxyRevertNote,
		Kind: ActionEdit, Path: p,
		Transform: func(in []byte) ([]byte, error) {
			if !sslProtocolsLine.Match(in) {
				return nil, fmt.Errorf("%s no longer sets ssl_protocols; re-scan before fixing", p)
			}
			return sslProtocolsLine.ReplaceAll(in, []byte("${1}ssl_protocols TLSv1.2 TLSv1.3;")), nil
		},
		AfterWrite: nginxReload,
	}}}, nil
}

var autoindexOnLine = regexp.MustCompile(`(?mi)^([ \t]*)autoindex[ \t]+on[ \t]*;`)

func buildNginxNoAutoindex(f model.Finding) (Fix, error) {
	p, err := singleConfig(f)
	if err != nil {
		return Fix{}, err
	}
	return Fix{Label: "Turn off directory listing", Kind: model.RemediationReview, IndividualOnly: true, Actions: []Action{{
		Label: "Set every `autoindex on;` in " + p + " to off, then reload nginx",
		Benefit: "Directories without an index file stop listing what is in them, so a stray backup or .env " +
			"beside the site is no longer one click away.",
		Warning: "A directory somebody meant to be browsable — a download mirror, a shared folder — stops listing " +
			"and answers 403 instead. Listing is sometimes on for one location on purpose; if so, put it back for " +
			"that location alone. " + proxyRevertNote,
		Kind: ActionEdit, Path: p,
		Transform: func(in []byte) ([]byte, error) {
			if !autoindexOnLine.Match(in) {
				return nil, fmt.Errorf("%s no longer turns autoindex on; re-scan before fixing", p)
			}
			return autoindexOnLine.ReplaceAll(in, []byte("${1}autoindex off;")), nil
		},
		AfterWrite: nginxReload,
	}}}, nil
}

// buildTraefikSecureAPI removes --api.insecure from the service's command
// list. The dashboard goes with it unless the operator routes api@internal
// through authentication, which is the Warning, and Traefik reads its flags
// at start, so the first alternative recreates the container fronting every
// other service and the second leaves that to the operator.
func buildTraefikSecureAPI(f model.Finding) (Fix, error) {
	where := f.Evidence["set-in"]
	flag, ok := strings.CutPrefix(where, "command: ")
	if !ok {
		return Fix{}, fmt.Errorf("finding %s is set by %q, not by a command flag", f.ID, where)
	}
	flag = strings.Trim(strings.TrimSpace(flag), `"`)
	p, err := composeKeyTarget(f, func(s compose.Service) bool {
		for _, c := range s.Command {
			if strings.Trim(strings.TrimSpace(c), `"`) == flag {
				return true
			}
		}
		return false
	})
	if err != nil {
		return Fix{}, err
	}
	svc := f.Service
	remove := func(d *compose.Doc) error {
		return d.RemoveSeqItem(svc, "command", func(n *yaml.Node) bool {
			return n.Kind == yaml.ScalarNode && strings.Trim(strings.TrimSpace(n.Value), `"`) == flag
		})
	}
	benefit := "The unauthenticated dashboard, and the map of every router and backend it shows, stops being " +
		"served to anyone who reaches port 8080."
	risk := "The dashboard is gone until you expose `api@internal` through a router with authentication. " +
		"The edit has a checkpoint and rolls back exactly."
	now := composeEdit(p, "Remove "+flag+" and recreate "+svc+" now", benefit,
		risk+" Recreating "+svc+" drops every connection through this proxy for the seconds it takes to start.", svc, remove)
	now.TakesEffectOn = ""
	now.AfterWrite = [][]string{{"docker", "compose", "-f", p, "up", "-d", svc}}
	later := composeEdit(p, "Remove "+flag+"; recreate "+svc+" yourself", benefit, risk+" "+recreateNote(svc), svc, remove)
	return Fix{Label: "Stop serving Traefik's dashboard without authentication", Kind: model.RemediationReview,
		IndividualOnly: true, Actions: []Action{now, later}}, nil
}

var caddyAdminLine = regexp.MustCompile(`(?m)^([ \t]*)admin[ \t]+[^\s{}#]+`)

// buildCaddyAdminLoopback puts the admin address back to Caddy's default in
// a host Caddyfile. Caddy validates the file before the reload, and the
// reload goes through the API on its old address, which is the last thing
// that address is used for.
func buildCaddyAdminLoopback(f model.Finding) (Fix, error) {
	p := f.Evidence["config"]
	if p == "" || f.Metadata["caddy_host"] != "true" {
		return Fix{}, fmt.Errorf("finding %s is not a host Caddyfile hostveil can edit and reload", f.ID)
	}
	return Fix{Label: "Move Caddy's admin API back to loopback", Kind: model.RemediationReview, IndividualOnly: true,
		Actions: []Action{{
			Label: "Set `admin localhost:2019` in " + p + ", then validate and reload Caddy",
			Benefit: "The API that can replace the proxy's whole configuration stops answering anyone but processes " +
				"on this host.",
			Warning: "Whatever calls the admin API from elsewhere — a deploy script, a config manager, a certificate " +
				"sidecar on another machine — stops being able to, and the proxy keeps serving until something needs " +
				"to change and then cannot. " + proxyRevertNote,
			Kind: ActionEdit, Path: p,
			Transform: func(in []byte) ([]byte, error) {
				loc := caddyAdminLine.FindSubmatchIndex(in)
				if loc == nil {
					return nil, fmt.Errorf("%s no longer sets admin; re-scan before fixing", p)
				}
				out := append([]byte{}, in[:loc[0]]...)
				out = append(out, in[loc[2]:loc[3]]...)
				out = append(out, "admin localhost:2019"...)
				return append(out, in[loc[1]:]...), nil
			},
			AfterWrite: [][]string{
				{"caddy", "validate", "--config", p, "--adapter", "caddyfile"},
				{"systemctl", "try-reload-or-restart", "caddy"},
			},
			// A reload sends the new config to the admin address the new
			// config names. After the rollback that is the exposed one again,
			// while the running Caddy listens on loopback since the fix, and
			// it refuses the request: "host not allowed: 0.0.0.0:2019", found
			// on a real Caddy by scripts/e2e/individual.sh. The rollback
			// sends the restored file to where the API is now.
			AfterRestore: [][]string{
				{"caddy", "validate", "--config", p, "--adapter", "caddyfile"},
				{"caddy", "reload", "--config", p, "--adapter", "caddyfile", "--address", "localhost:2019", "--force"},
			},
		}}}, nil
}
