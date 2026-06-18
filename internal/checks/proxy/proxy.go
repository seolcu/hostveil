// Package proxy scans the host's reverse-proxy configurations
// (nginx, caddy) for the rules from FR-014:
//
//   - reverse_proxy.server_tokens: server_tokens leaks the version.
//   - reverse_proxy.security_headers: missing common security
//     response headers (X-Content-Type-Options, X-Frame-Options,
//     Referrer-Policy, Strict-Transport-Security).
//   - reverse_proxy.exposed_path: a vhost exposes a sensitive
//     hidden path (.git, .env, .htpasswd, .svn, .hg).
//   - reverse_proxy.no_rate_limit: an auth-related location has
//     no rate limiting configured.
//
// The v3.0.0 release supports nginx's http {} block syntax and
// caddy's Caddyfile snippet syntax. Other proxies (traefik, envoy,
// haproxy) are out of scope for v3.0.0.
package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/model"
)

// commonPaths is the list of config files the scanner inspects.
var commonPaths = []string{
	"/etc/nginx/nginx.conf",
	"/etc/nginx/conf.d",
	"/etc/caddy/Caddyfile",
	"/etc/caddy/caddyfile",
}

// Run implements checks.Run.
func Run(ctx context.Context) (checks.Result, error) {
	var findings []model.Finding
	now := time.Now().UTC()
	for _, p := range commonPaths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			entries, _ := os.ReadDir(p)
			for _, e := range entries {
				fp := filepath.Join(p, e.Name())
				if isConfFile(e.Name()) {
					if f, ok := scanNginxFile(fp, now); ok {
						findings = append(findings, f...)
					}
				}
			}
			continue
		}
		if isConfFile(p) {
			if f, ok := scanNginxFile(p, now); ok {
				findings = append(findings, f...)
			}
		} else if isCaddyfile(p) {
			if f, ok := scanCaddyfile(p, now); ok {
				findings = append(findings, f...)
			}
		}
	}
	if len(findings) == 0 {
		return checks.Result{
			Skipped: &model.CategorySkip{
				Category: model.CategoryReverseProxy,
				Reason:   "not_applicable",
				Detail:   "no nginx or caddy config found in well-known locations",
			},
		}, nil
	}
	return checks.Result{Findings: findings}, nil
}

func isConfFile(name string) bool {
	return strings.HasSuffix(name, ".conf")
}

func isCaddyfile(name string) bool {
	base := filepath.Base(name)
	return base == "Caddyfile" || base == "caddyfile"
}

// nginxParser is a line-based scanner for nginx's http {} block. It
// looks for the directives in the spec and emits findings as it
// goes. We do not implement a full nginx parser; we just look for
// the keywords in context.
type nginxParser struct {
	lines    []string
	serverTokens string
	headers       map[string]bool
	locations     []string
}

func scanNginxFile(path string, now time.Time) ([]model.Finding, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	p := &nginxParser{
		lines:    strings.Split(string(b), "\n"),
		headers:  map[string]bool{},
	}
	var out []model.Finding
	inServer := false
	for i, line := range p.lines {
		trim := strings.TrimSpace(line)
		// Strip trailing comments.
		if c := strings.Index(trim, "#"); c >= 0 {
			trim = strings.TrimSpace(trim[:c])
		}
		if trim == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trim, "server "):
			inServer = true
		case strings.HasPrefix(trim, "location "):
			p.locations = append(p.locations, strings.TrimSpace(trim[len("location "):]))
		case strings.HasPrefix(trim, "server_tokens "):
			p.serverTokens = strings.TrimSpace(trim[len("server_tokens "):])
		case strings.HasPrefix(trim, "add_header "):
			parts := strings.Fields(trim)
			if len(parts) >= 2 {
				p.headers[strings.ToLower(parts[1])] = true
			}
		case trim == "}":
			inServer = false
			// When the server block closes, evaluate its findings.
			if inServer {
				// already evaluated; not reachable.
			}
		}
		_ = i
	}
	// File-level rules: server_tokens leaks version, missing
	// security headers, exposed paths, missing rate limit on auth
	// locations.
	if strings.EqualFold(p.serverTokens, "on") || p.serverTokens == "" {
		// Default behavior in nginx is to emit the nginx version
		// unless server_tokens off; we treat the default as a
		// finding.
		out = append(out, model.Finding{
			ID:       "finding-reverse_proxy.server_tokens-" + path,
			Category: model.CategoryReverseProxy,
			RuleID:   "reverse_proxy.server_tokens",
			Severity: model.SeverityLow,
			Title:    "Reverse proxy leaks the server version",
			Description: "Server tokens are not disabled in " + path + ". A remote attacker can use the version to look up known CVEs.",
			EntityRefs: []model.EntityRef{
				{Kind: model.EntityRefKindConfigFile, Display: path},
			},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		})
	}
	for _, h := range []string{"x-content-type-options", "x-frame-options", "referrer-policy", "strict-transport-security"} {
		if !p.headers[h] {
			out = append(out, model.Finding{
				ID:       "finding-reverse_proxy.security_headers-" + path + "-" + h,
				Category: model.CategoryReverseProxy,
				RuleID:   "reverse_proxy.security_headers",
				Severity: model.SeverityLow,
				Title:    "Missing security response header: " + h,
				Description: "The " + h + " response header is not set in " + path + ".",
				EntityRefs: []model.EntityRef{
					{Kind: model.EntityRefKindConfigFile, Display: path},
				},
				State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
			})
		}
	}
	for _, loc := range p.locations {
		// Exposed sensitive paths
		for _, sensitive := range []string{".git", ".env", ".htpasswd", ".svn", ".hg"} {
			if strings.Contains(loc, sensitive) {
				out = append(out, model.Finding{
					ID:       "finding-reverse_proxy.exposed_path-" + path + "-" + loc,
					Category: model.CategoryReverseProxy,
					RuleID:   "reverse_proxy.exposed_path",
					Severity: model.SeverityHigh,
					Title:    "Sensitive hidden path is exposed: " + sensitive,
					Description: "Location \"" + loc + "\" in " + path + " serves a sensitive hidden path (" + sensitive + ").",
					EntityRefs: []model.EntityRef{
						{Kind: model.EntityRefKindConfigFile, Display: path + ":" + loc},
					},
					State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
				})
			}
		}
		// Missing rate limit on auth-related locations
		lower := strings.ToLower(loc)
		if strings.Contains(lower, "auth") || strings.Contains(lower, "login") || strings.Contains(lower, "signin") {
			if !strings.Contains(lower, "limit_req") {
				out = append(out, model.Finding{
					ID:       "finding-reverse_proxy.no_rate_limit-" + path + "-" + loc,
					Category: model.CategoryReverseProxy,
					RuleID:   "reverse_proxy.no_rate_limit",
					Severity: model.SeverityMedium,
					Title:    "Auth endpoint has no rate limit",
					Description: "Location \"" + loc + "\" in " + path + " is auth-related and has no limit_req configured.",
					EntityRefs: []model.EntityRef{
						{Kind: model.EntityRefKindConfigFile, Display: path + ":" + loc},
					},
					State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
				})
			}
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// caddyParser is a line-based Caddyfile scanner.
type caddyParser struct {
	lines        []string
	serverHeader bool
	headers      map[string]bool
}

func scanCaddyfile(path string, now time.Time) ([]model.Finding, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	p := &caddyParser{
		lines:   strings.Split(string(b), "\n"),
		headers: map[string]bool{},
	}
	var out []model.Finding
	for _, line := range p.lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "header ") {
			parts := strings.Fields(trim)
			if len(parts) >= 2 {
				p.headers[strings.ToLower(parts[1])] = true
			}
		}
		if strings.HasPrefix(trim, "Server") {
			p.serverHeader = true
		}
	}
	if !p.serverHeader {
		// Caddy's default is to emit the version; the explicit
		// `Server` off is the right behavior.
		out = append(out, model.Finding{
			ID:       "finding-reverse_proxy.server_tokens-" + path,
			Category: model.CategoryReverseProxy,
			RuleID:   "reverse_proxy.server_tokens",
			Severity: model.SeverityLow,
			Title:    "Reverse proxy leaks the server version",
			Description: "The Server response header is not set in " + path + ".",
			EntityRefs: []model.EntityRef{
				{Kind: model.EntityRefKindConfigFile, Display: path},
			},
			State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
		})
	}
	for _, h := range []string{"x-content-type-options", "x-frame-options", "referrer-policy", "strict-transport-security"} {
		if !p.headers[h] {
			out = append(out, model.Finding{
				ID:       "finding-reverse_proxy.security_headers-" + path + "-" + h,
				Category: model.CategoryReverseProxy,
				RuleID:   "reverse_proxy.security_headers",
				Severity: model.SeverityLow,
				Title:    "Missing security response header: " + h,
				Description: "The " + h + " response header is not set in " + path + ".",
				EntityRefs: []model.EntityRef{
					{Kind: model.EntityRefKindConfigFile, Display: path},
				},
				State: model.StateNew, FirstSeenAt: now, LastSeenAt: now,
			})
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
