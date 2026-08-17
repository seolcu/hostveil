package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// nginxRoot lays out a fake /etc/nginx. Files are named relative to the root
// and directories are created as needed.
func nginxRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// noDocker is a host with no Docker at all, which is the arrangement every
// nginx test wants: the Traefik half then has nothing to say and cannot
// degrade the domain.
func noDocker() platform.Env { return checktest.New().Without("docker").Env() }

func has(fs []model.Finding, id string) *model.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestDeprecatedTLSVersionsAreFound(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf": "http {\n  include conf.d/*.conf;\n}\n",
		"conf.d/tls.conf": "server {\n" +
			"  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n" +
			"}\n",
	})
	c := &Checker{NginxRoot: root}

	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatalf("nothing went unexamined here: %v", err)
	}
	f := has(fs, "proxy.tls-deprecated-protocols")
	if f == nil {
		t.Fatalf("expected proxy.tls-deprecated-protocols, got %v", fs)
	}
	if f.Evidence["protocols"] != "TLSv1, TLSv1.1" {
		t.Errorf("evidence names %q; it has to name which ones, because the fix is to "+
			"remove exactly those", f.Evidence["protocols"])
	}
	if f.Severity != model.SeverityMedium {
		t.Errorf("severity = %v, want medium", f.Severity)
	}
}

// The trap the whole rule turns on. "tlsv1" is a prefix of "tlsv1.2" and
// "tlsv1.3", so a substring or prefix test flags the *recommended*
// configuration — and the finding would then be on every correctly configured
// nginx there is, which is worse than not having the rule.
func TestModernTLSIsNotFlagged(t *testing.T) {
	for _, line := range []string{
		"ssl_protocols TLSv1.2 TLSv1.3;",
		"ssl_protocols TLSv1.3;",
		"  ssl_protocols   TLSv1.2   TLSv1.3 ;",
	} {
		root := nginxRoot(t, map[string]string{"nginx.conf": line + "\n"})
		fs, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
		if err != nil {
			t.Fatal(err)
		}
		if f := has(fs, "proxy.tls-deprecated-protocols"); f != nil {
			t.Errorf("%q was flagged, naming %q", line, f.Evidence["protocols"])
		}
	}
}

// A commented-out directive is not a directive. nginx configs are full of the
// distribution's own examples left in place with a # in front, and a rule that
// read them would fire on a stock install that has changed nothing.
func TestCommentedDirectivesAreIgnored(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf": "# ssl_protocols TLSv1 TLSv1.1;\n#autoindex on;\n",
	})
	fs, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a commented example is not a setting, got %v", fs)
	}
}

func TestDirectoryListingIsFound(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf":         "include sites-enabled/*;\n",
		"sites-enabled/site": "server {\n  location /files {\n    autoindex on;\n  }\n}\n",
	})
	fs, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if f := has(fs, "proxy.directory-listing"); f == nil {
		t.Fatalf("expected proxy.directory-listing, got %v", fs)
	}
	if f := has(fs, "proxy.directory-listing"); f.Evidence["config"] == "" {
		t.Error("the finding must name the file, or the operator cannot act on it")
	}
}

func TestAutoindexOffIsNotAFinding(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "autoindex off;\n"})
	fs, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("autoindex off is the default and is not a finding, got %v", fs)
	}
}

// Following include is the whole reason this reads more than one file.
// Debian's nginx.conf is almost empty — the configuration lives in conf.d and
// sites-enabled — so a checker that read only the top-level file would audit
// an empty shell on the distribution most of this program's users run. That is
// the mistake internal/check/ssh was fixed for with sshd_config's Include.
func TestIncludesAreFollowed(t *testing.T) {
	root := nginxRoot(t, map[string]string{
		"nginx.conf":           "user www-data;\ninclude conf.d/*.conf;\ninclude sites-enabled/*;\n",
		"conf.d/ssl.conf":      "ssl_protocols TLSv1.1 TLSv1.2;\n",
		"sites-enabled/vhost":  "location / { autoindex on; }\n",
		"sites-available/unus": "ssl_protocols TLSv1;\n", // not included, must not be read
	})
	fs, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if has(fs, "proxy.tls-deprecated-protocols") == nil || has(fs, "proxy.directory-listing") == nil {
		t.Fatalf("both included files must be read, got %v", fs)
	}
	// sites-available is the staging area on Debian: a vhost there is not
	// served, and reporting it would be a finding about a file nginx never
	// loads.
	if f := has(fs, "proxy.tls-deprecated-protocols"); f.Evidence["protocols"] == "TLSv1, TLSv1.1" {
		t.Error("a file nginx does not include was read; sites-available is not served")
	}
}

// Traefik's insecure API, in the three spellings people actually write.
func TestTraefikInsecureAPIIsFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  compose.Service
	}{
		{"command flag", compose.Service{Image: "traefik:v3.1", Command: []string{"--api.insecure=true", "--providers.docker"}}},
		{"bare command flag", compose.Service{Image: "traefik", Command: []string{"--api.insecure"}}},
		{"environment", compose.Service{Image: "docker.io/library/traefik:v2", Environment: compose.Environment{"TRAEFIK_API_INSECURE": "true"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Checker{
				NginxRoot: filepath.Join(t.TempDir(), "no-nginx"),
				Discover: func(context.Context, platform.CommandRunner) ([]compose.Project, []string, error) {
					return []compose.Project{{
						Name: "edge", File: "/opt/stacks/edge/docker-compose.yml",
						Services: map[string]compose.Service{"proxy": tc.svc},
					}}, nil, nil
				},
			}
			fs, err := c.Check(context.Background(), checktest.New().Docker("27.0").Env())
			if err != nil {
				t.Fatalf("nothing went unexamined: %v", err)
			}
			f := has(fs, "proxy.traefik-api-insecure")
			if f == nil {
				t.Fatalf("expected proxy.traefik-api-insecure, got %v", fs)
			}
			if f.Severity != model.SeverityHigh {
				t.Errorf("severity = %v, want high: an unauthenticated dashboard lists every "+
					"backend address behind the proxy", f.Severity)
			}
			if f.Evidence["set-in"] == "" {
				t.Error("the finding must say where the setting is, or it cannot be removed")
			}
		})
	}
}

// A Traefik that does not turn the insecure API on is not a finding, and
// neither is a service that merely has "traefik" somewhere in it.
func TestTraefikWithoutTheInsecureAPIIsClean(t *testing.T) {
	for _, tc := range []struct {
		name string
		svc  compose.Service
	}{
		{"api without insecure", compose.Service{Image: "traefik:v3.1", Command: []string{"--api=true", "--providers.docker"}}},
		{"explicitly off", compose.Service{Image: "traefik:v3.1", Command: []string{"--api.insecure=false"}}},
		{"env explicitly off", compose.Service{Image: "traefik", Environment: compose.Environment{"TRAEFIK_API_INSECURE": "false"}}},
		// The image decides which program reads the flag. A service named
		// "traefik" running something else would not.
		{"not traefik", compose.Service{Image: "nginx:alpine", Command: []string{"--api.insecure=true"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Checker{
				NginxRoot: filepath.Join(t.TempDir(), "no-nginx"),
				Discover: func(context.Context, platform.CommandRunner) ([]compose.Project, []string, error) {
					return []compose.Project{{Name: "edge", Services: map[string]compose.Service{"traefik": tc.svc}}}, nil, nil
				},
			}
			fs, err := c.Check(context.Background(), checktest.New().Docker("27.0").Env())
			if err != nil {
				t.Fatal(err)
			}
			if f := has(fs, "proxy.traefik-api-insecure"); f != nil {
				t.Errorf("flagged %v", f.Evidence)
			}
		})
	}
}

// A host with neither surface has no proxy to have an opinion about, and the
// axis is renormalized away rather than scored on an absence. This is the
// opposite of the firewall domain, where absence *is* the finding — nobody is
// insecure for not running a reverse proxy.
func TestAHostWithNoProxyIsSkipped(t *testing.T) {
	c := &Checker{NginxRoot: filepath.Join(t.TempDir(), "nope")}
	ok, why := c.Available(context.Background(), noDocker())
	if ok {
		t.Fatal("a host with no nginx and no Docker has no reverse proxy to audit")
	}
	if why == "" {
		t.Error("a skip with no reason is the thing every domain here has to avoid")
	}
}

// An unreadable config is a gap, not a clean result — the ordinary non-root
// scan, and the case this whole codebase is most insistent about.
func TestUnreadableConfigDegradesRatherThanPassing(t *testing.T) {
	root := nginxRoot(t, map[string]string{"nginx.conf": "include conf.d/*.conf;\n"})
	secret := filepath.Join(root, "conf.d", "ssl.conf")
	if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("ssl_protocols TLSv1;\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files, so the gap cannot be staged")
	}

	_, err := (&Checker{NginxRoot: root}).Check(context.Background(), noDocker())
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("an unreadable include must degrade the domain, got %v", err)
	}
	if !contains(partial.Reason, "ssl.conf") {
		t.Errorf("the reason must name what went unread, got %q", partial.Reason)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
