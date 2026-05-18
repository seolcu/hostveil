package compose

import (
	"testing"
)

const testCompose = `
version: "3.8"
services:
  vaultwarden:
    image: vaultwarden/server:1.30.1
    user: "1000:1000"
    ports:
      - "8080:80"
    environment:
      DOMAIN: "http://vault.example.com"
      SIGNUPS_ALLOWED: "true"
    volumes:
      - vaultwarden-data:/data
      - ./config:/config:ro
    cap_add:
      - NET_ADMIN
    restart: unless-stopped

  jellyfin:
    image: jellyfin/jellyfin:latest
    user: root
    ports:
      - "0.0.0.0:8096:8096"
      - target: 7359
        published: 7359
        protocol: udp
    volumes:
      - jellyfin-config:/config
      - /media:/media:ro
    environment:
      JELLYFIN_PublishedServerUrl: http://media.local:8096
    privileged: true

volumes:
  vaultwarden-data:
  jellyfin-config:
`

func TestParseBasic(t *testing.T) {
	cf, err := Parse([]byte(testCompose))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cf.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(cf.Services))
	}

	vw, ok := cf.Services["vaultwarden"]
	if !ok {
		t.Fatal("vaultwarden service not found")
	}

	if vw.Image != "vaultwarden/server:1.30.1" {
		t.Errorf("expected vaultwarden/server:1.30.1, got %s", vw.Image)
	}

	if vw.User != "1000:1000" {
		t.Errorf("expected user 1000:1000, got %s", vw.User)
	}

	if len(vw.Ports) != 1 {
		t.Fatalf("expected 1 port, got %d", len(vw.Ports))
	}

	if vw.Ports[0].Published != 8080 {
		t.Errorf("expected published 8080, got %d", vw.Ports[0].Published)
	}

	if vw.Ports[0].Target != 80 {
		t.Errorf("expected target 80, got %d", vw.Ports[0].Target)
	}

	if vw.Environment["DOMAIN"] != "http://vault.example.com" {
		t.Errorf("expected DOMAIN env, got %s", vw.Environment["DOMAIN"])
	}

	if len(vw.Volumes) != 2 {
		t.Fatalf("expected 2 volumes, got %d", len(vw.Volumes))
	}

	if vw.Volumes[1].ReadOnly != true {
		t.Error("expected second volume to be read-only")
	}

	if len(vw.CapAdd) != 1 || vw.CapAdd[0] != "NET_ADMIN" {
		t.Error("expected cap_add NET_ADMIN")
	}

	jf, ok := cf.Services["jellyfin"]
	if !ok {
		t.Fatal("jellyfin service not found")
	}

	if !jf.Privileged {
		t.Error("expected jellyfin to be privileged")
	}

	if len(jf.Ports) != 2 {
		t.Fatalf("expected 2 ports for jellyfin, got %d", len(jf.Ports))
	}

	if jf.Ports[1].Protocol != "udp" {
		t.Errorf("expected udp protocol for second port, got %s", jf.Ports[1].Protocol)
	}

	if len(cf.Volumes) != 2 {
		t.Errorf("expected 2 volumes, got %d", len(cf.Volumes))
	}
}

func TestParseErrors(t *testing.T) {
	_, err := Parse([]byte(`invalid: yaml: `))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseEmptyFile(t *testing.T) {
	_, err := Parse([]byte(``))
	if err != nil {
		t.Fatalf("Parse failed on empty: %v", err)
	}
}
