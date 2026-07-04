package composeaudit

import (
	"testing"
)

func TestDetectInlineSecrets(t *testing.T) {
	f := openCompose(t, `services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: changeme
  cache:
    image: redis:7
    environment:
      REDIS_PASSWORD: ${REDIS_PASSWORD}
`)
	findings := detectInlineSecrets(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.dr005") {
		t.Fatal("expected compose.dr005 for hardcoded POSTGRES_PASSWORD")
	}
	for _, f := range findings {
		if f.ID == "compose.dr005" && f.Service == "cache" {
			t.Error("compose.dr005 should not flag interpolated REDIS_PASSWORD")
		}
	}
}

func TestCheckDockerSocket_LongSyntax(t *testing.T) {
	f := openCompose(t, `services:
  agent:
    image: portainer/agent
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
`)
	findings := checkDockerSocket(f, "agent", Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds016") {
		t.Error("expected compose.ds016 for long-syntax docker socket mount")
	}
}

func TestCheckSensitiveHostMount_LongSyntax(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: /etc
        target: /host-etc
`)
	findings := checkSensitiveHostMount(f, "web", Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds017") {
		t.Error("expected compose.ds017 for long-syntax /etc mount")
	}
}
