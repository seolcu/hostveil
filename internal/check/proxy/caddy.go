package proxy

import (
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// Caddy is audited for the two settings that matter and nothing else.
//
//   - **The admin API.** Caddy serves a REST endpoint that can read and replace
//     its entire running configuration, and it has no authentication of its
//     own. The default binds it to localhost:2019, which is safe; the `admin`
//     global option or the CADDY_ADMIN environment variable can move it onto
//     every interface, and then anyone who reaches the port can point the
//     proxy fronting every other service wherever they like. That is a worse
//     exposure than Traefik's insecure dashboard, which only reads.
//   - **`file_server browse`**, Caddy's spelling of nginx's `autoindex on`.
//
// What nginx is also audited for and Caddy is not: deprecated TLS versions.
// Caddy's `protocols` subdirective accepts tls1.2 and tls1.3 and nothing
// older, so there is no configuration of it that this rule could flag.
//
// Only the Caddyfile is read. A JSON configuration is reported as a coverage
// gap rather than read as clean, because a Caddyfile's absence says nothing
// about what the JSON beside it contains.

// caddyDefaultConfig is where both the distribution packages and the official
// image keep the Caddyfile.
const caddyDefaultConfig = "/etc/caddy/Caddyfile"

// caddyGlobal is the parent recorded for a line inside the global options
// block — a block opened by a bare `{` at the top of the file, which is the
// only place `admin` is valid.
const caddyGlobal = "{"

// caddyLine is one directive of a Caddyfile: its tokens, and the first token
// of the line that opened the block it sits in ("" at top level).
type caddyLine struct {
	tokens []string
	parent string
}

// caddyLines tokenizes a Caddyfile into directives.
//
// The grammar is line-oriented, unlike nginx's: a newline ends a directive, a
// token that is exactly `{` opens a block and one that is exactly `}` closes
// it. Braces inside a token are placeholders (`{env.ADMIN}`), not blocks,
// which is why they are compared as whole unquoted tokens. `#` starts a
// comment only at the start of a token, and quotes and backticks group a token
// across whitespace. A heredoc (`<<MARKER`) runs to the line that starts with
// the marker, and its body is skipped rather than read as directives: it is
// content the proxy serves, and an `admin :2019` inside a respond body is not
// a setting.
func caddyLines(body string) []caddyLine {
	var out []caddyLine
	var stack []string
	parent := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1]
	}
	heredoc := ""
	for _, line := range strings.Split(body, "\n") {
		if heredoc != "" {
			// The closing marker may carry the rest of the directive after it
			// (`HTML 200`); those arguments are not directives either.
			if f := strings.Fields(line); len(f) > 0 && f[0] == heredoc {
				heredoc = ""
			}
			continue
		}
		var cur []string
		flush := func() {
			if len(cur) > 0 {
				out = append(out, caddyLine{tokens: cur, parent: parent()})
			}
			cur = nil
		}
		for _, t := range caddyTokens(line) {
			switch {
			case t.text == "{" && !t.quoted:
				open := caddyGlobal
				if len(cur) > 0 {
					open = cur[0]
				}
				flush()
				stack = append(stack, open)
			case t.text == "}" && !t.quoted:
				flush()
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			default:
				cur = append(cur, t.text)
			}
		}
		if n := len(cur); n > 0 && strings.HasPrefix(cur[n-1], "<<") && len(cur[n-1]) > 2 {
			heredoc = cur[n-1][2:]
		}
		flush()
	}
	return out
}

type caddyToken struct {
	text   string
	quoted bool
}

// caddyTokens splits one line. A quoted token that runs past the end of the
// line is cut there: Caddy allows it, and what it holds is a value rather than
// a directive this package reads.
func caddyTokens(line string) []caddyToken {
	var out []caddyToken
	var b strings.Builder
	in, quoted := false, false
	end := func() {
		if in {
			out = append(out, caddyToken{text: b.String(), quoted: quoted})
		}
		b.Reset()
		in, quoted = false, false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			end()
		case c == '#' && !in:
			return out
		case (c == '"' || c == '`') && !in:
			in, quoted = true, true
			j := i + 1
			for ; j < len(line) && line[j] != c; j++ {
				if c == '"' && line[j] == '\\' && j+1 < len(line) {
					j++
				}
				b.WriteByte(line[j])
			}
			i = j
			end()
		default:
			in = true
			b.WriteByte(c)
		}
	}
	end()
	return out
}

// caddyAdmin returns the admin address the global options set, and whether
// they set one at all.
func caddyAdmin(lines []caddyLine) (string, bool) {
	for _, l := range lines {
		if l.parent != caddyGlobal || l.tokens[0] != "admin" {
			continue
		}
		if len(l.tokens) < 2 {
			// `admin { ... }` with no address keeps the default.
			return "", false
		}
		return l.tokens[1], true
	}
	return "", false
}

// caddyBrowse reports whether any file_server turns directory listing on,
// either inline (`file_server browse`, `file_server /media/* browse`) or as a
// subdirective of its block.
func caddyBrowse(lines []caddyLine) bool {
	for _, l := range lines {
		switch {
		case l.tokens[0] == "file_server":
			for _, t := range l.tokens[1:] {
				if t == "browse" {
					return true
				}
			}
		case l.tokens[0] == "browse" && l.parent == "file_server":
			return true
		}
	}
	return false
}

// adminExposed reports whether an admin listen address is reachable from
// anything but this host (or, inside a container, anything but the
// container). It also returns the port, when the address names one.
//
// A placeholder (`{env.ADMIN}`) is not judged: its value is not in the file,
// and inventing one would be a finding about a guess.
func adminExposed(addr string) (exposed bool, port string) {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "off" || strings.Contains(addr, "{") {
		return false, ""
	}
	if network, rest, ok := strings.Cut(addr, "/"); ok {
		if strings.HasPrefix(network, "unix") {
			return false, ""
		}
		addr = rest
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch {
	case host == "":
		return true, p
	case strings.EqualFold(host, "localhost"):
		return false, p
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.IsLoopback() {
		return false, p
	}
	return true, p
}

// caddyFiles returns every file reachable from entry through import
// directives, plus the ones it could not read. resolve maps an import pattern
// as the config writes it onto a host path; for the packaged Caddy it is the
// identity, for a container it goes through the bind mounts.
func caddyFiles(entry string, resolve func(string) (string, bool)) (files, unread []string) {
	seen := map[string]bool{}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		if depth > 10 || seen[p] {
			return
		}
		seen[p] = true
		b, err := platform.ReadFileBounded(p, 4<<20)
		if err != nil {
			unread = append(unread, p)
			return
		}
		files = append(files, p)
		for _, l := range caddyLines(string(b)) {
			if l.tokens[0] != "import" || len(l.tokens) < 2 {
				continue
			}
			pattern := l.tokens[1]
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(p), pattern)
			} else if host, ok := resolve(pattern); ok {
				pattern = host
			} else {
				continue
			}
			// A snippet name (`import common`) matches no file and is
			// already in this one.
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
	walk(entry, 0)
	sort.Strings(files)
	sort.Strings(unread)
	return files, unread
}

// caddyAudit is what one Caddy configuration says.
type caddyAudit struct {
	files     []string
	unread    []string
	admin     string // the address set by the global options, if any
	adminFile string
	browse    []string // files turning directory listing on
}

func auditCaddyfile(entry string, resolve func(string) (string, bool)) caddyAudit {
	var a caddyAudit
	a.files, a.unread = caddyFiles(entry, resolve)
	for _, f := range a.files {
		b, err := platform.ReadFileBounded(f, 4<<20)
		if err != nil {
			a.unread = append(a.unread, f)
			continue
		}
		lines := caddyLines(string(b))
		if addr, ok := caddyAdmin(lines); ok && a.adminFile == "" {
			a.admin, a.adminFile = addr, f
		}
		if caddyBrowse(lines) {
			a.browse = append(a.browse, f)
		}
	}
	return a
}

// auditHostCaddy reads a packaged Caddy's configuration directory. It returns
// the findings, the files that list directories, and the coverage gap if any.
func auditHostCaddy(root string) (findings []model.Finding, browse []string, gap string, covered bool) {
	entry := filepath.Join(root, "Caddyfile")
	if _, err := os.Stat(entry); err != nil {
		if os.IsNotExist(err) {
			if js, _ := filepath.Glob(filepath.Join(root, "*.json")); len(js) > 0 {
				return nil, nil, "Caddy is configured with JSON (" + strings.Join(js, ", ") + "), which is not audited", false
			}
			return nil, nil, "", false
		}
		return nil, nil, "could not read " + entry + " — Caddy's configuration was not audited; re-run with sudo", false
	}
	a := auditCaddyfile(entry, func(p string) (string, bool) { return p, true })
	if len(a.files) == 0 {
		return nil, nil, "could not read " + entry + " — Caddy's configuration was not audited; re-run with sudo", false
	}
	if len(a.unread) > 0 {
		gap = "could not read " + strings.Join(a.unread, ", ") + " — directives there were not audited; re-run with sudo"
	}
	if exposed, _ := adminExposed(a.admin); exposed {
		findings = append(findings, caddyAdminFinding(a.admin, "admin "+a.admin+" in "+a.adminFile,
			model.SeverityHigh, "", a.adminFile))
	}
	return findings, a.browse, gap, true
}

// isCaddy decides from the image reference, as isTraefik does.
func isCaddy(s compose.Service) bool {
	return imageBase(s.Image) == "caddy"
}

func imageBase(ref string) string {
	img := strings.ToLower(ref)
	if i := strings.IndexAny(img, ":@"); i >= 0 {
		img = img[:i]
	}
	if i := strings.LastIndex(img, "/"); i >= 0 {
		img = img[i+1:]
	}
	return img
}

// containerPath maps a path inside a container onto the host through the
// service's bind mounts, the longest matching target winning.
func containerPath(svc compose.Service, p string) (string, bool) {
	best := -1
	var out string
	for _, v := range svc.Volumes {
		if !v.Bind || v.Target == "" {
			continue
		}
		t := path.Clean(v.Target)
		if p != t && !strings.HasPrefix(p, t+"/") {
			continue
		}
		if len(t) > best {
			best = len(t)
			out = filepath.Join(v.Source, strings.TrimPrefix(p, t))
		}
	}
	return out, best >= 0
}

// caddyConfigArg returns the --config path from the service's command, or the
// image's default.
func caddyConfigArg(svc compose.Service) string {
	for i, arg := range svc.Command {
		a := strings.TrimSpace(arg)
		if v, ok := strings.CutPrefix(a, "--config="); ok {
			return v
		}
		if a == "--config" && i+1 < len(svc.Command) {
			return strings.TrimSpace(svc.Command[i+1])
		}
	}
	return caddyDefaultConfig
}

// auditContainerCaddy audits one Caddy service. The admin address is judged
// from the Caddyfile when it sets one, since an explicit option overrides the
// CADDY_ADMIN default, and from the environment otherwise.
func auditContainerCaddy(p compose.Project, name string, svc compose.Service) (findings []model.Finding, browse []string, gap string) {
	cfg := caddyConfigArg(svc)
	var a caddyAudit
	switch host, mounted := containerPath(svc, cfg); {
	case strings.HasSuffix(strings.ToLower(cfg), ".json"):
		gap = "service " + name + " runs Caddy with a JSON configuration (" + cfg + "), which is not audited"
	case mounted:
		a = auditCaddyfile(host, func(q string) (string, bool) { return containerPath(svc, q) })
		switch {
		case len(a.files) == 0:
			gap = "could not read " + host + " (service " + name + "'s Caddyfile) — its configuration was not audited"
		case len(a.unread) > 0:
			gap = "could not read " + strings.Join(a.unread, ", ") + " — directives there were not audited"
		}
	case cfg != caddyDefaultConfig:
		gap = "service " + name + " reads its Caddyfile from " + cfg + ", which is not a bind mount hostveil can read"
	}
	// Neither mounted nor overridden: the image's own Caddyfile, which keeps
	// the default admin address and serves no listing.

	addr, where := a.admin, "admin "+a.admin+" in "+a.adminFile
	if a.adminFile == "" {
		for k, v := range svc.Environment {
			if k == "CADDY_ADMIN" {
				addr, where = v, "environment: CADDY_ADMIN="+v
			}
		}
	}
	if exposed, port := adminExposed(addr); exposed {
		// Inside a container, a non-loopback admin address is reachable from
		// every container on the same network; it is reachable from off-host
		// only when the port is also published. The first needs a foothold,
		// the second needs nothing.
		sev := model.SeverityMedium
		if port == "" {
			port = "2019"
		}
		for _, pt := range svc.Ports {
			if pt.ContainerPort == port && pt.ExposedOnAllInterfaces() {
				sev = model.SeverityHigh
			}
		}
		extra := []model.FindingOption{model.WithEvidence("image", svc.Image)}
		if p.File != "" {
			extra = append(extra, model.WithMetadata("file", p.File), model.WithEvidence("file", p.File))
		}
		if p.Name != "" {
			extra = append(extra, model.WithEvidence("project", p.Name))
		}
		findings = append(findings, caddyAdminFinding(addr, where, sev, name, a.adminFile, extra...))
	}
	return findings, a.browse, gap
}

func caddyAdminFinding(addr, where string, sev model.Severity, service, file string, extra ...model.FindingOption) model.Finding {
	desc := "Caddy's admin API is listening on " + strconv.Quote(addr) + " rather than on loopback. " +
		"It has no authentication, and it is not a status page: a single request can read the running configuration or replace it, " +
		"which means anyone who reaches the port can reroute every site this proxy serves, point it at a server of their own, or turn it off."
	if service != "" && sev != model.SeverityHigh {
		desc += " The port is not published to the host, so reaching it takes a foothold in another container on the same network first — which is exactly what a compromised neighbour has."
	}
	fix := "Set the global option back to the default (`admin localhost:2019`), or `admin off` if nothing calls the API, then `systemctl reload caddy`. " +
		"If something off the host genuinely manages Caddy, use the `remote` admin listener, which requires client certificates, rather than exposing this one."
	if service != "" {
		fix = "Keep the admin address on loopback: remove the non-loopback CADDY_ADMIN value or `admin` option (" + where + "), " +
			"and do not publish port 2019. Recreate the container afterwards — Caddy reads this at start. " +
			"If something outside the container genuinely manages Caddy, use the `remote` admin listener, which requires client certificates."
	}
	opts := []model.FindingOption{
		model.WithDescription(desc),
		model.WithHowToFix(fix),
		model.WithEvidence("address", addr),
		model.WithEvidence("set-in", where),
	}
	if service != "" {
		opts = append(opts, model.WithService(service))
	}
	if file != "" {
		opts = append(opts, model.WithEvidence("config", file))
	}
	opts = append(opts, extra...)
	return model.NewFinding("proxy.admin-api-exposed",
		"The reverse proxy's admin API is reachable without authentication",
		sev, model.SourceProxy, model.RemediationManual, opts...)
}
