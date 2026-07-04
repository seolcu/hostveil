package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetVolumeMounts_ShortSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data:ro
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mounts := f.GetVolumeMounts("web")
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts[0].Source != "/var/run/docker.sock" {
		t.Errorf("mount[0].Source = %q", mounts[0].Source)
	}
}

func TestGetVolumeMounts_LongSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  agent:
    image: portainer/agent
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mounts := f.GetVolumeMounts("agent")
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Source != "/var/run/docker.sock" {
		t.Errorf("mount.Source = %q", mounts[0].Source)
	}
}

func TestGetEnvironment_MapAndList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    environment:
      DB_PASSWORD: secret123
  api:
    image: myapp
    environment:
      - API_KEY=abc123
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	webEnv := f.GetEnvironment("web")
	if webEnv["DB_PASSWORD"] != "secret123" {
		t.Errorf("web env = %#v", webEnv)
	}
	apiEnv := f.GetEnvironment("api")
	if apiEnv["API_KEY"] != "abc123" {
		t.Errorf("api env = %#v", apiEnv)
	}
}

func TestSetAndDeleteEnvironmentValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    environment:
      DB_PASSWORD: secret123
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetEnvironmentValue("web", "DB_PASSWORD", "${DB_PASSWORD}"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(data), "${DB_PASSWORD}") {
		t.Errorf("expected placeholder in file:\n%s", string(data))
	}

	f, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteEnvironmentKey("web", "DB_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containsAll(string(data), "DB_PASSWORD") {
		t.Errorf("expected key removed:\n%s", string(data))
	}
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !containsString(s, part) {
			return false
		}
	}
	return true
}

func containsString(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexString(s, sub) >= 0)
}

func indexString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
