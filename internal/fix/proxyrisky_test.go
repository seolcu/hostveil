package fix

import (
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func proxyFinding(id string, ev, meta map[string]string) model.Finding {
	var opts []model.FindingOption
	for k, v := range ev {
		opts = append(opts, model.WithEvidence(k, v))
	}
	for k, v := range meta {
		opts = append(opts, model.WithMetadata(k, v))
	}
	return model.NewFinding(id, "t", model.SeverityMedium, model.SourceProxy, model.RemediationReview, opts...)
}

func TestNginxTLSRewritesEveryProtocolsLineAndReloads(t *testing.T) {
	fx, err := buildNginxModernTLS(proxyFinding("proxy.tls-deprecated-protocols", map[string]string{"config": "/etc/nginx/nginx.conf"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	in := "http {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # old\n    server {\n\tssl_protocols TLSv1.1;\n    }\n}\n"
	out, err := fx.Actions[0].Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := "http {\n    ssl_protocols TLSv1.2 TLSv1.3; # old\n    server {\n\tssl_protocols TLSv1.2 TLSv1.3;\n    }\n}\n"
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	if !slices.Equal(fx.Actions[0].AfterWrite[0], []string{"nginx", "-t"}) {
		t.Errorf("nginx must check the live config before the reload: %v", fx.Actions[0].AfterWrite)
	}
}

func TestNginxFindingOverSeveralFilesIsDeclined(t *testing.T) {
	_, err := buildNginxModernTLS(proxyFinding("proxy.tls-deprecated-protocols",
		map[string]string{"config": "/etc/nginx/nginx.conf, /etc/nginx/sites-enabled/a"}, nil))
	if err == nil {
		t.Fatal("one edit cannot settle a directive set in two files")
	}
}

func TestAutoindexIsTurnedOffNotDeleted(t *testing.T) {
	fx, err := buildNginxNoAutoindex(proxyFinding("proxy.directory-listing", map[string]string{"config": "/etc/nginx/sites-enabled/default"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	out, err := fx.Actions[0].Transform([]byte("location /files/ {\n    autoindex on;\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "location /files/ {\n    autoindex off;\n}\n" {
		t.Errorf("got %q", out)
	}
}

func TestCaddyAdminGoesBackToLoopback(t *testing.T) {
	fx, err := buildCaddyAdminLoopback(proxyFinding("proxy.admin-api-exposed",
		map[string]string{"config": "/etc/caddy/Caddyfile"}, map[string]string{"caddy_host": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := fx.Actions[0].Transform([]byte("{\n\tadmin 0.0.0.0:2019\n\temail me@example.com\n}\n\nexample.com {\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "\tadmin localhost:2019\n\temail") {
		t.Errorf("got:\n%s", out)
	}
	if _, err := buildCaddyAdminLoopback(proxyFinding("proxy.admin-api-exposed", map[string]string{"config": "/srv/Caddyfile"}, nil)); err == nil {
		t.Error("a container's Caddyfile must be declined")
	}
}

func TestTraefikRequiresACommandFlag(t *testing.T) {
	f := proxyFinding("proxy.traefik-api-insecure", map[string]string{"set-in": "environment: TRAEFIK_API_INSECURE=true"},
		map[string]string{"file": "/srv/compose.yml"})
	if _, err := buildTraefikSecureAPI(f); err == nil {
		t.Fatal("an environment setting is not a command flag to remove")
	}
}

func TestTraefikFlagLeavesTheRestOfTheCommand(t *testing.T) {
	f := proxyFinding("proxy.traefik-api-insecure", map[string]string{"set-in": "command: --api.insecure=true"},
		map[string]string{"file": "/srv/compose.yml"})
	f.Service = "traefik"
	fx, err := buildTraefikSecureAPI(f)
	if err != nil {
		t.Fatal(err)
	}
	in := "services:\n  traefik:\n    image: traefik:v3\n    command:\n      - --api.insecure=true\n      - --providers.docker=true\n"
	out, err := fx.Actions[0].Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "services:\n  traefik:\n    image: traefik:v3\n    command:\n      - --providers.docker=true\n" {
		t.Errorf("got:\n%s", out)
	}
	if got := fx.Actions[0].AfterWrite[0]; !slices.Equal(got, []string{"docker", "compose", "-f", "/srv/compose.yml", "up", "-d", "traefik"}) {
		t.Errorf("recreate argv %v", got)
	}
}

// A reload goes to the admin address in the file being loaded, which after a
// rollback is the exposed one the running Caddy no longer listens on. The
// rollback must address the API where the fix put it.
func TestCaddyRollbackReloadsThroughLoopback(t *testing.T) {
	fx, err := buildCaddyAdminLoopback(proxyFinding("proxy.admin-api-exposed",
		map[string]string{"config": "/etc/caddy/Caddyfile"}, map[string]string{"caddy_host": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	r := fx.Actions[0].AfterRestore
	if len(r) != 2 || !slices.Contains(r[1], "--address") || !slices.Contains(r[1], "localhost:2019") {
		t.Errorf("rollback runs %v; it must reload through localhost:2019", r)
	}
}
