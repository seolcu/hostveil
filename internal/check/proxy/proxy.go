// Package proxy audits the reverse proxy in front of everything else.
//
// It is the component this program's audience is most likely to have and least
// likely to have configured: somebody running Jellyfin and Nextcloud at home
// puts nginx, Caddy or Traefik on 443 and points the world at it. Every other
// domain here looks at something behind that.
//
// Two surfaces, because there are two ways people run one and covering only
// the fashionable one would leave the common one unexamined — the same
// argument the ports domain makes about a natively installed database that a
// Compose audit cannot see:
//
//   - nginx and Caddy as packages, read from /etc/nginx and /etc/caddy,
//     following include and import directives.
//   - Traefik and Caddy as containers, read from the Compose files the
//     container domain already discovers. Traefik's most dangerous setting is
//     almost always on the service's command line rather than in a config
//     file, because that is how every tutorial writes it; a Caddy container's
//     Caddyfile is read through its bind mount. What is read from Caddy, and
//     why, is in caddy.go.
//
// # What is deliberately not audited
//
// **A proxy serving plain HTTP.** The obvious rule — listening on 80 with no
// TLS anywhere — accuses two configurations that are completely correct: a
// vhost whose only job is `return 301 https://$host$request_uri`, and a proxy
// behind something else that already terminates TLS (a tunnel, a load
// balancer, Cloudflare). Neither is distinguishable from the config, and a
// rule that flags most people's working setup erodes the whole domain. This is
// the same test net.ipv4.ip_forward fails in the sysctl package.
//
// **Missing security headers.** HSTS, CSP and the rest are worth having and
// they are not what gets a self-hoster breached; a domain that spends its
// severity budget on them teaches people to ignore it.
//
// **Anything about certificates.** Expiry and issuer are facts about the
// network, not about a file, and a scanner reading a config cannot see them.
package proxy

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Checker reports weaknesses in a host's reverse proxy.
type Checker struct {
	// NginxRoot is the nginx configuration directory; overridable for tests.
	NginxRoot string
	// CaddyRoot is the packaged Caddy's configuration directory. Empty skips
	// the packaged-Caddy half, which is what keeps a test that sets only
	// NginxRoot from reading the /etc/caddy of whatever host runs it.
	CaddyRoot string
	// Discover finds Compose projects. nil means the real one — injected so a
	// test can exercise the Traefik half without a Docker daemon.
	Discover func(ctx context.Context, r platform.CommandRunner) ([]compose.Project, []string, error)
	// Fail2banConfDir is fail2ban's configuration directory (holding
	// jail.local and jail.d/); overridable for tests, same pattern as
	// NginxRoot.
	Fail2banConfDir string
}

// New returns a proxy checker reading the standard locations.
func New() *Checker { return &Checker{NginxRoot: "/etc/nginx", CaddyRoot: "/etc/caddy"} }

// Source identifies the reverse-proxy domain.
func (*Checker) Source() model.Source { return model.SourceProxy }

// Available requires something that could be a reverse proxy.
//
// A host with no nginx or Caddy configuration and no reachable Docker daemon has
// no proxy for this domain to have an opinion about, and the axis is
// renormalized away rather than scored on an absence. That is the opposite of
// the firewall domain, where absence *is* the finding — nobody is insecure for
// not running a reverse proxy.
func (c *Checker) Available(ctx context.Context, env platform.Env) (bool, string) {
	if ok, why := platform.AuditableOS(); !ok {
		return false, why
	}
	if isDir(c.root()) || (c.CaddyRoot != "" && isDir(c.CaddyRoot)) {
		return true, ""
	}
	if ok, _ := platform.DockerReachable(ctx, env.Runner); ok {
		return true, ""
	}
	return false, "no reverse proxy found — no " + c.root() + " or /etc/caddy, and no reachable Docker daemon to look for one in"
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func (c *Checker) root() string {
	if c.NginxRoot != "" {
		return c.NginxRoot
	}
	return "/etc/nginx"
}

// Check reads both surfaces and reports what each could not cover.
func (c *Checker) Check(ctx context.Context, env platform.Env) ([]model.Finding, error) {
	var cov check.Coverage
	var findings []model.Finding
	// Directory listing is one finding however many proxies turn it on, so
	// each surface reports the files and the finding is built once below.
	var nginxListing, caddyListing []string

	if isDir(c.root()) {
		fs, listing, unread := auditNginx(c.root())
		findings = append(findings, fs...)
		nginxListing = listing
		cov.Covered(1)
		if len(unread) > 0 {
			cov.Missed(0, "could not read "+strings.Join(unread, ", ")+
				" — directives there were not audited; re-run with sudo")
		}
		findings = append(findings, c.auditScanProtection(ctx, env.Runner, &cov)...)
	}

	if c.CaddyRoot != "" && isDir(c.CaddyRoot) {
		fs, listing, gap, covered := auditHostCaddy(c.CaddyRoot)
		findings = append(findings, fs...)
		caddyListing = append(caddyListing, listing...)
		if covered {
			cov.Covered(1)
		}
		if gap != "" {
			cov.Missed(0, gap)
		}
	}

	if ok, why := platform.DockerReachable(ctx, env.Runner); ok {
		projects, unparsed, err := c.discover(ctx, env.Runner)
		switch {
		case err != nil:
			cov.Missed(0, "cannot enumerate Compose projects — a containerised proxy was not audited")
		default:
			cov.Covered(1)
			fs, listing, gaps := auditCompose(projects)
			findings = append(findings, fs...)
			caddyListing = append(caddyListing, listing...)
			for _, g := range gaps {
				cov.Missed(0, g)
			}
			if len(unparsed) > 0 {
				cov.Missed(0, "could not read "+strings.Join(unparsed, ", ")+
					" — a proxy defined there was not audited")
			}
		}
	} else if why != "" {
		// Only a gap when there is a daemon to fail to reach. "Docker not
		// installed" on a host running nginx from a package is a complete
		// answer, not a blind spot — the same direction dockerd's config
		// merge got wrong.
		if !strings.Contains(why, "not installed") {
			cov.Missed(0, why+" — a containerised proxy was not audited")
		}
	}

	if len(nginxListing) > 0 || len(caddyListing) > 0 {
		findings = append(findings, directoryListingFinding(nginxListing, caddyListing))
	}

	sort.Slice(findings, func(i, j int) bool { return findings[i].ID < findings[j].ID })
	return findings, cov.Err()
}

func (c *Checker) discover(ctx context.Context, r platform.CommandRunner) ([]compose.Project, []string, error) {
	if c.Discover != nil {
		return c.Discover(ctx, r)
	}
	return compose.Discover(ctx, r)
}

// auditCompose looks for a containerised proxy serving its own control plane
// without authentication, and for a containerised Caddy listing directories.
// It returns the findings, the Caddyfiles that turn listing on, and what it
// could not read.
func auditCompose(projects []compose.Project) (out []model.Finding, listing, gaps []string) {
	for _, p := range projects {
		for _, name := range p.ServiceNames() {
			svc := p.Services[name]
			switch {
			case isTraefik(svc):
				if where, ok := traefikInsecureAPI(svc); ok {
					out = append(out, traefikFinding(p, name, svc, where))
				}
			case isCaddy(svc):
				fs, browse, gap := auditContainerCaddy(p, name, svc)
				out = append(out, fs...)
				listing = append(listing, browse...)
				if gap != "" {
					gaps = append(gaps, gap)
				}
			}
		}
	}
	return out, listing, gaps
}

// isTraefik decides from the image reference. The name is not enough — a
// service may be called anything — and the image is what actually determines
// which program reads the flags below.
func isTraefik(s compose.Service) bool {
	return imageBase(s.Image) == "traefik"
}

// traefikInsecureAPI reports whether this service turns on the unauthenticated
// API, and where it says so.
//
// Three spellings, because Traefik accepts all three and the tutorials are
// split between them. The command line first: `--api.insecure=true` is what
// nearly every copied compose file carries.
func traefikInsecureAPI(s compose.Service) (string, bool) {
	for _, arg := range s.Command {
		a := strings.ToLower(strings.TrimSpace(arg))
		a = strings.TrimPrefix(a, "\"")
		a = strings.TrimSuffix(a, "\"")
		switch {
		case a == "--api.insecure" || a == "--api.insecure=true":
			return "command: " + strings.TrimSpace(arg), true
		case strings.HasPrefix(a, "--api.insecure="):
			// Anything but true is an explicit off, which is the point of
			// writing it out.
			if strings.TrimPrefix(a, "--api.insecure=") == "true" {
				return "command: " + strings.TrimSpace(arg), true
			}
		}
	}
	for k, v := range s.Environment {
		if strings.EqualFold(k, "TRAEFIK_API_INSECURE") && isTrue(v) {
			return "environment: " + k + "=" + v, true
		}
	}
	return "", false
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

func traefikFinding(p compose.Project, name string, svc compose.Service, where string) model.Finding {
	opts := []model.FindingOption{
		model.WithService(name),
		model.WithDescription(
			"Traefik's API and dashboard are running in insecure mode, which means no authentication at all. " +
				"That dashboard is not a status page: it lists every router, service and backend address this proxy knows about, " +
				"so anyone who reaches it learns the internal address of everything behind the proxy and which hostnames route where. " +
				"It is served on port 8080 by default, and the setting is in nearly every Traefik tutorial because it is what makes the dashboard work with no further effort."),
		model.WithHowToFix(
			"Remove the insecure API setting (" + where + "). If you want the dashboard, expose it through a router with authentication instead: " +
				"keep `--api=true` without `--api.insecure`, add a router for `api@internal` on a hostname you control, and put a basicauth or forward-auth middleware in front of it. " +
				"Recreate the container afterwards — Traefik reads these at start."),
		model.WithEvidence("set-in", where),
		model.WithEvidence("image", svc.Image),
	}
	if p.File != "" {
		opts = append(opts, model.WithMetadata("file", p.File), model.WithEvidence("file", p.File))
	}
	if p.Name != "" {
		opts = append(opts, model.WithEvidence("project", p.Name))
	}
	kind := model.RemediationReview
	if !strings.HasPrefix(where, "command: ") || p.File == "" {
		kind = model.RemediationManual
		opts = append(opts, model.WithWhyNoFix("Hostveil removes the flag from a Compose `command:` list; this one is set "+
			"through the environment or outside a Compose file it can edit."))
	}
	return model.NewFinding("proxy.traefik-api-insecure",
		"The reverse proxy's dashboard is served with no authentication",
		model.SeverityHigh, model.SourceProxy, kind, opts...)
}

// auditNginx reads the nginx configuration and returns findings, the files
// that turn directory listing on, and the files it could not read.
func auditNginx(root string) ([]model.Finding, []string, []string) {
	files, unread := nginxFiles(root)

	weak := map[string][]string{}    // file -> the offending protocol names
	listing := map[string]struct{}{} // files with autoindex on

	for _, f := range files {
		b, err := platform.ReadFileBounded(f, 4<<20)
		if err != nil {
			unread = append(unread, f)
			continue
		}
		for _, st := range statements(string(b)) {
			if protos := weakProtocols(st); len(protos) > 0 {
				weak[f] = append(weak[f], protos...)
			}
			if autoindexOn(st) {
				listing[f] = struct{}{}
			}
		}
	}

	var out []model.Finding
	if len(weak) > 0 {
		out = append(out, weakTLSFinding(weak))
	}
	names := make([]string, 0, len(listing))
	for f := range listing {
		names = append(names, f)
	}
	sort.Strings(names)
	sort.Strings(unread)
	return out, names, unread
}

// deprecatedTLS is the set nothing should still be offering. TLS 1.0 and 1.1
// were deprecated by RFC 8996 in 2021 and every current browser refuses them,
// so a server still offering them is not serving anybody — it is only widening
// what an attacker can negotiate down to. SSLv2 and SSLv3 are older still.
var deprecatedTLS = []string{"sslv2", "sslv3", "tlsv1", "tlsv1.1"}

// statements splits an nginx configuration into directives.
//
// Line-oriented reading is the obvious approach and it is wrong in the
// direction that matters. nginx's grammar is terminated by `;` and blocks are
// delimited by braces, so `location /files { autoindex on; }` is three
// statements on one line — and a reader that took a line at a time would miss
// the setting entirely. A false negative is the failure this whole package is
// least allowed: it reports a proxy as clean.
//
// Comments are stripped first, per line, because `#` runs to the end of a line
// regardless of the braces around it — and a distribution's nginx.conf is
// mostly its own examples left in place behind one.
func statements(body string) [][]string {
	var sb strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	var out [][]string
	for _, raw := range strings.FieldsFunc(sb.String(), func(r rune) bool {
		return r == ';' || r == '{' || r == '}'
	}) {
		if fields := strings.Fields(raw); len(fields) > 0 {
			out = append(out, fields)
		}
	}
	return out
}

// weakProtocols returns the deprecated protocols an ssl_protocols directive
// enables.
func weakProtocols(fields []string) []string {
	if len(fields) < 2 || fields[0] != "ssl_protocols" {
		return nil
	}
	var found []string
	for _, f := range fields[1:] {
		got := strings.ToLower(f)
		for _, bad := range deprecatedTLS {
			// Exact, not prefix: "tlsv1" must not match "tlsv1.2", which is
			// the whole reason this list is compared rather than searched for.
			if got == bad {
				found = append(found, f)
			}
		}
	}
	return found
}

// autoindexOn reports whether a directive turns directory listing on.
func autoindexOn(fields []string) bool {
	return len(fields) == 2 && fields[0] == "autoindex" && strings.EqualFold(fields[1], "on")
}

func weakTLSFinding(weak map[string][]string) model.Finding {
	files := make([]string, 0, len(weak))
	for f := range weak {
		files = append(files, f)
	}
	sort.Strings(files)

	seen := map[string]bool{}
	var protos []string
	for _, f := range files {
		for _, p := range weak[f] {
			if key := strings.ToLower(p); !seen[key] {
				seen[key] = true
				protos = append(protos, p)
			}
		}
	}
	kind, why := singleFileFix(files, "ssl_protocols")
	return model.NewFinding("proxy.tls-deprecated-protocols",
		"The proxy still offers TLS versions nothing should accept",
		model.SeverityMedium, model.SourceProxy, kind, model.WithWhyNoFix(why),
		model.WithDescription(
			"An `ssl_protocols` line here enables "+strings.Join(protos, ", ")+". "+
				"RFC 8996 deprecated TLS 1.0 and 1.1 in 2021 and every current browser refuses them, so offering them serves no client that could not already connect — "+
				"it only widens what an attacker in the middle can negotiate the connection down to."),
		model.WithHowToFix(
			"Set `ssl_protocols TLSv1.2 TLSv1.3;` in "+strings.Join(files, ", ")+", then `nginx -t` to check the file parses and `systemctl reload nginx` to apply it. "+
				"Reload rather than restart: nginx keeps serving from the configuration it already loaded, so a broken file looks like nothing at all until the next restart."),
		model.WithEvidence("protocols", strings.Join(protos, ", ")),
		model.WithEvidence("config", strings.Join(files, ", ")),
	)
}

func directoryListingFinding(nginx, caddy []string) model.Finding {
	var what, fix []string
	if len(nginx) > 0 {
		what = append(what, "`autoindex on` makes nginx")
		fix = append(fix, "Remove `autoindex on;` (or set it to `off`) in "+strings.Join(nginx, ", ")+", then `nginx -t` and `systemctl reload nginx`.")
	}
	if len(caddy) > 0 {
		what = append(what, "`file_server browse` makes Caddy")
		fix = append(fix, "Remove `browse` from `file_server` in "+strings.Join(caddy, ", ")+", then `caddy validate` and `systemctl reload caddy` (or recreate the container).")
	}
	files := append(append([]string{}, nginx...), caddy...)
	kind, why := singleFileFix(nginx, "autoindex")
	if len(caddy) > 0 {
		kind, why = model.RemediationManual, "Hostveil edits nginx's autoindex but not Caddy's file_server, which may be served from inside a container it cannot reload."
	}
	return model.NewFinding("proxy.directory-listing",
		"The proxy lists the contents of directories it serves",
		model.SeverityMedium, model.SourceProxy, kind, model.WithWhyNoFix(why),
		model.WithDescription(
			strings.Join(what, ", and ")+" generate a browsable listing for any directory with no index file. "+
				"Everything in the directory is then enumerable by anyone who can reach it — backups left beside the site, a stray .env, a database dump, the file somebody meant to delete. "+
				"It is a disclosure of what exists rather than of one file, which is what makes it worth more than the single file anybody had in mind."),
		model.WithHowToFix(
			strings.Join(fix, " ")+
				" If a directory really is meant to be browsable, keep listing on for that path alone rather than for the whole site."),
		model.WithEvidence("config", strings.Join(files, ", ")),
	)
}

// nginxFiles returns every configuration file reachable from root, following
// include directives, plus the paths it could not read.
//
// Includes are followed rather than assumed, because nginx's own layout puts
// almost nothing in nginx.conf: Debian ships conf.d/*.conf and sites-enabled/*,
// and a rule that read only the top-level file would audit an empty shell on
// the distribution most of this program's users run. That is the same mistake
// internal/check/ssh was fixed for with sshd_config's Include.
func nginxFiles(root string) ([]string, []string) {
	var out, unread []string
	seen := map[string]bool{}

	var walk func(path string, depth int)
	walk = func(path string, depth int) {
		// A bound rather than a cycle check: nginx itself refuses to nest
		// includes forever, and a config that reaches this depth is not one
		// hostveil should be following anyway.
		if depth > 10 || seen[path] {
			return
		}
		seen[path] = true

		b, err := platform.ReadFileBounded(path, 4<<20)
		if err != nil {
			unread = append(unread, path)
			return
		}
		out = append(out, path)

		for _, fields := range statements(string(b)) {
			if len(fields) != 2 || fields[0] != "include" {
				continue
			}
			pattern := fields[1]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(root, pattern)
			}
			matches, gerr := filepath.Glob(pattern)
			if gerr != nil {
				continue
			}
			for _, m := range matches {
				if fi, serr := os.Stat(m); serr == nil && !fi.IsDir() {
					walk(m, depth+1)
				}
			}
		}
	}

	walk(filepath.Join(root, "nginx.conf"), 0)
	// The top-level file being unreadable is the ordinary non-root case and
	// says nothing on its own; it is reported through Coverage by the caller.
	if len(out) == 0 {
		return nil, unread
	}
	sort.Strings(out)
	return out, unread
}

// singleFileFix is the remediation for an nginx finding spread over files.
// A fix edits one file and then reloads, so a directive in one file is
// Review and the same directive in several is Manual: editing one of them
// would leave the others in force while the re-check named only those.
func singleFileFix(files []string, directive string) (model.RemediationKind, string) {
	if len(files) == 1 {
		return model.RemediationReview, ""
	}
	return model.RemediationManual, "`" + directive + "` is set in " + strconv.Itoa(len(files)) +
		" files, and a fix edits one file at a time; changing one would leave the others in force."
}
