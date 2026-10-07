package proxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// caddyChecker audits a fake /etc/caddy and nothing else.
func caddyChecker(t *testing.T, files map[string]string) *Checker {
	t.Helper()
	return &Checker{
		NginxRoot: filepath.Join(t.TempDir(), "no-nginx"),
		CaddyRoot: nginxRoot(t, files),
	}
}

func TestCaddyAdminAddresses(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		exposed bool
	}{
		{":2019", true},
		{"0.0.0.0:2019", true},
		{"[::]:2019", true},
		{"10.0.0.5:2019", true},
		{"tcp/0.0.0.0:2019", true},
		{"admin.example.com:2019", true},
		{"localhost:2019", false},
		{"127.0.0.1:2019", false},
		{"127.0.0.2:2019", false},
		{"[::1]:2019", false},
		{"off", false},
		{"unix//run/caddy-admin.sock", false},
		// The value is not in the file; judging it would be judging a guess.
		{"{env.CADDY_ADMIN_ADDR}", false},
		{"", false},
	} {
		if got, _ := adminExposed(tc.addr); got != tc.exposed {
			t.Errorf("adminExposed(%q) = %v, want %v", tc.addr, got, tc.exposed)
		}
	}
}

func TestCaddyAdminOnEveryInterfaceIsFound(t *testing.T) {
	c := caddyChecker(t, map[string]string{
		"Caddyfile": "{\n\temail ops@example.com\n\tadmin 0.0.0.0:2019\n}\n\nexample.com {\n\treverse_proxy app:8080\n}\n",
	})
	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatalf("nothing went unexamined: %v", err)
	}
	f := has(fs, "proxy.admin-api-exposed")
	if f == nil {
		t.Fatalf("expected proxy.admin-api-exposed, got %v", fs)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high: the API replaces the proxy's whole configuration", f.Severity)
	}
	if f.Evidence["address"] != "0.0.0.0:2019" {
		t.Errorf("address evidence = %q", f.Evidence["address"])
	}
	// A host Caddyfile is one line and a reload, so it is offered.
	if f.Remediation != model.RemediationReview {
		t.Errorf("remediation = %v, want Review", f.Remediation)
	}
}

// admin is a global option. The same word inside a site block is a matcher
// name, a path, a respond body — anything but the setting — and a heredoc body
// is content the proxy serves.
func TestCaddyAdminOutsideTheGlobalBlockIsNotTheSetting(t *testing.T) {
	c := caddyChecker(t, map[string]string{
		"Caddyfile": "example.com {\n" +
			"\t# admin 0.0.0.0:2019\n" +
			"\trespond <<TXT\n" +
			"\t\tadmin :2019\n" +
			"\t\tTXT 200\n" +
			"\thandle /admin {\n\t\tadmin :2019\n\t}\n" +
			"}\n",
	})
	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if f := has(fs, "proxy.admin-api-exposed"); f != nil {
		t.Errorf("flagged %v", f.Evidence)
	}
}

func TestCaddyDefaultAdminIsClean(t *testing.T) {
	for _, body := range []string{
		"example.com {\n\tfile_server\n}\n",
		"{\n\tadmin {\n\t\torigins localhost\n\t}\n}\nexample.com {\n\tfile_server\n}\n",
		"{\n\tadmin off\n}\n",
	} {
		c := caddyChecker(t, map[string]string{"Caddyfile": body})
		fs, err := c.Check(context.Background(), noDocker())
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 0 {
			t.Errorf("%q: flagged %v", body, fs)
		}
	}
}

func TestCaddyBrowseIsDirectoryListing(t *testing.T) {
	for _, body := range []string{
		"files.example.com {\n\tfile_server browse\n}\n",
		"files.example.com {\n\tfile_server /media/* browse\n}\n",
		"files.example.com {\n\tfile_server {\n\t\troot /srv\n\t\tbrowse\n\t}\n}\n",
		"files.example.com {\n\tfile_server { browse }\n}\n",
	} {
		c := caddyChecker(t, map[string]string{"Caddyfile": body})
		fs, err := c.Check(context.Background(), noDocker())
		if err != nil {
			t.Fatal(err)
		}
		f := has(fs, "proxy.directory-listing")
		if f == nil {
			t.Errorf("%q: expected proxy.directory-listing, got %v", body, fs)
			continue
		}
		if !strings.Contains(f.Description, "file_server browse") {
			t.Errorf("the description must name Caddy's spelling, got %q", f.Description)
		}
	}
}

// Only file_server's own browse. A route or matcher named browse is not it.
func TestCaddyBrowseElsewhereIsNotListing(t *testing.T) {
	c := caddyChecker(t, map[string]string{
		"Caddyfile": "example.com {\n\t@browse path /browse/*\n\thandle @browse {\n\t\treverse_proxy app:8080\n\t}\n\tfile_server\n}\n",
	})
	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	if f := has(fs, "proxy.directory-listing"); f != nil {
		t.Errorf("flagged %v", f.Evidence)
	}
}

// The Debian package's Caddyfile is a stub for exactly this reason: sites go
// in files it imports, and a rule that read only the top-level file would
// audit an empty shell.
func TestCaddyImportsAreFollowed(t *testing.T) {
	c := caddyChecker(t, map[string]string{
		"Caddyfile":           "import sites/*.caddy\nimport common\n",
		"sites/files.caddy":   "files.example.com {\n\tfile_server browse\n}\n",
		"sites/global.caddy":  "",
		"sites/ignored.conf":  "{\n\tadmin :2019\n}\n",
		"conf.d/unused.caddy": "{\n\tadmin :2019\n}\n",
	})
	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	f := has(fs, "proxy.directory-listing")
	if f == nil || !strings.Contains(f.Evidence["config"], "sites/files.caddy") {
		t.Fatalf("expected a listing finding naming sites/files.caddy, got %v", fs)
	}
	if has(fs, "proxy.admin-api-exposed") != nil {
		t.Error("read a file nothing imports")
	}
}

// One finding for the host, however many proxies list directories.
func TestNginxAndCaddyListingIsOneFinding(t *testing.T) {
	c := &Checker{
		NginxRoot: nginxRoot(t, map[string]string{"nginx.conf": "http { autoindex on; }\n"}),
		CaddyRoot: nginxRoot(t, map[string]string{"Caddyfile": ":80 {\n\tfile_server browse\n}\n"}),
	}
	fs, err := c.Check(context.Background(), noDocker())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		if f.ID == "proxy.directory-listing" {
			n++
			for _, want := range []string{"autoindex on", "file_server browse"} {
				if !strings.Contains(f.Description, want) {
					t.Errorf("description does not name %q: %q", want, f.Description)
				}
			}
		}
	}
	if n != 1 {
		t.Errorf("%d directory-listing findings, want 1", n)
	}
}

// "I could not look" is never "nothing there".
func TestCaddyUnreadableConfigDegrades(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	c := caddyChecker(t, map[string]string{"Caddyfile": "{\n\tadmin :2019\n}\n"})
	if err := os.Chmod(filepath.Join(c.CaddyRoot, "Caddyfile"), 0); err != nil {
		t.Fatal(err)
	}
	_, err := c.Check(context.Background(), noDocker())
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("an unreadable Caddyfile must degrade the domain, got %v", err)
	}
}

func TestCaddyJSONConfigIsAGapNotClean(t *testing.T) {
	c := caddyChecker(t, map[string]string{"caddy.json": `{"admin":{"listen":":2019"}}`})
	_, err := c.Check(context.Background(), noDocker())
	var pe *check.PartialError
	if !errors.As(err, &pe) {
		t.Fatalf("a JSON configuration is unread, not clean: got %v", err)
	}
}

func TestAHostWithOnlyCaddyIsAvailable(t *testing.T) {
	c := caddyChecker(t, map[string]string{"Caddyfile": ""})
	if ok, why := c.Available(context.Background(), noDocker()); !ok {
		t.Fatalf("a packaged Caddy is a reverse proxy: %s", why)
	}
}

func TestCaddyLinesTracksBlocks(t *testing.T) {
	got := caddyLines("{\n\tadmin \"0.0.0.0:2019\" # note\n}\nexample.com, www.example.com {\n\tfile_server {\n\t\tbrowse\n\t}\n\trespond `a } b` 200\n}\n")
	want := []caddyLine{
		{tokens: []string{"admin", "0.0.0.0:2019"}, parent: caddyGlobal},
		{tokens: []string{"example.com,", "www.example.com"}, parent: ""},
		{tokens: []string{"file_server"}, parent: "example.com,"},
		{tokens: []string{"browse"}, parent: "file_server"},
		{tokens: []string{"respond", "a } b", "200"}, parent: "example.com,"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("caddyLines:\n got %v\nwant %v", got, want)
	}
}

// --- containers ---

func caddyService(t *testing.T, svc compose.Service) []model.Finding {
	t.Helper()
	fs, err := composeCaddy(t, svc)
	if err != nil {
		t.Fatalf("nothing went unexamined: %v", err)
	}
	return fs
}

func composeCaddy(t *testing.T, svc compose.Service) ([]model.Finding, error) {
	t.Helper()
	c := &Checker{
		NginxRoot: filepath.Join(t.TempDir(), "no-nginx"),
		Discover: func(context.Context, platform.CommandRunner) ([]compose.Project, []string, error) {
			return []compose.Project{{
				Name: "edge", File: "/opt/stacks/edge/docker-compose.yml",
				Services: map[string]compose.Service{"caddy": svc},
			}}, nil, nil
		},
	}
	return c.Check(context.Background(), checktest.New().Docker("27.0").Env())
}

func TestCaddyContainerWithTheImageDefaultIsClean(t *testing.T) {
	fs := caddyService(t, compose.Service{Image: "caddy:2-alpine"})
	if len(fs) != 0 {
		t.Errorf("the image's own Caddyfile keeps admin on loopback, got %v", fs)
	}
}

func TestCaddyContainerAdminEnv(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports []compose.Port
		want  model.Severity
	}{
		// Reachable from every container on the network, which takes a
		// foothold in one of them first.
		{"unpublished", nil, model.SeverityMedium},
		{"published to loopback", []compose.Port{{HostIP: "127.0.0.1", HostPort: "2019", ContainerPort: "2019", Published: true}}, model.SeverityMedium},
		// Reachable from off the host by anyone.
		{"published", []compose.Port{{HostPort: "2019", ContainerPort: "2019", Published: true}}, model.SeverityHigh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := caddyService(t, compose.Service{
				Image:       "docker.io/library/caddy:2",
				Environment: compose.Environment{"CADDY_ADMIN": "0.0.0.0:2019"},
				Ports:       tc.ports,
			})
			f := has(fs, "proxy.admin-api-exposed")
			if f == nil {
				t.Fatalf("expected proxy.admin-api-exposed, got %v", fs)
			}
			if f.Severity != tc.want {
				t.Errorf("severity = %v, want %v", f.Severity, tc.want)
			}
			if f.Service != "caddy" || f.Evidence["file"] == "" {
				t.Errorf("the finding must name the service and its compose file: %q %v", f.Service, f.Evidence)
			}
		})
	}
}

func TestCaddyContainerMountedCaddyfile(t *testing.T) {
	dir := nginxRoot(t, map[string]string{
		"Caddyfile":        "{\n\tadmin :2019\n}\nimport /etc/caddy/sites/*\n",
		"sites/files.conf": "files.example.com {\n\tfile_server browse\n}\n",
	})
	fs := caddyService(t, compose.Service{
		Image: "caddy",
		// An explicit option overrides the environment's default.
		Environment: compose.Environment{"CADDY_ADMIN": "localhost:2019"},
		Volumes:     []compose.Volume{{Source: dir, Target: "/etc/caddy", Bind: true, ReadOnly: true}},
	})
	if f := has(fs, "proxy.admin-api-exposed"); f == nil || !strings.Contains(f.Evidence["set-in"], "Caddyfile") {
		t.Errorf("expected the mounted Caddyfile's admin option, got %v", fs)
	}
	if f := has(fs, "proxy.directory-listing"); f == nil || !strings.Contains(f.Evidence["config"], filepath.Join(dir, "sites/files.conf")) {
		t.Errorf("an absolute import must be followed through the bind mount, got %v", fs)
	}
}

func TestCaddyContainerConfigItCannotReadIsAGap(t *testing.T) {
	for _, svc := range []compose.Service{
		{Image: "caddy", Command: compose.StringOrList{"caddy", "run", "--config", "/config/caddy.json"}},
		{Image: "caddy", Command: compose.StringOrList{"caddy", "run", "--config=/srv/Caddyfile"}},
		{Image: "caddy", Volumes: []compose.Volume{{Source: "/nonexistent/hostveil-test", Target: "/etc/caddy", Bind: true}}},
	} {
		_, err := composeCaddy(t, svc)
		var pe *check.PartialError
		if !errors.As(err, &pe) {
			t.Errorf("%+v: expected a coverage gap, got %v", svc, err)
		}
	}
}

// A heredoc's closing marker may carry the directive's remaining arguments.
// Missing that swallowed the rest of the file, so everything after the first
// respond body went unread — the false clean this package is least allowed.
func TestCaddyDirectivesAfterAHeredocAreRead(t *testing.T) {
	got := caddyLines("example.com {\n\trespond <<HTML\n\t\t<p>hi</p>\n\t\tHTML 200\n\tfile_server browse\n}\n")
	if !caddyBrowse(got) {
		t.Errorf("file_server browse after a heredoc was not read: %v", got)
	}
}
