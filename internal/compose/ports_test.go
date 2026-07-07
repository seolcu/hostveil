package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestrictPortBindings_LongSyntaxMapping(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    ports:
      - target: 80
        published: 8080
        host_ip: 0.0.0.0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := f.RestrictPortBindings("web", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected port restriction to change the file")
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, `host_ip: 127.0.0.1`) && !strings.Contains(out, `host_ip: "127.0.0.1"`) {
		t.Errorf("expected host_ip set to 127.0.0.1\n%s", out)
	}
}

func TestRestrictPortBindings_MixedSyntaxPreservesLongForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    ports:
      - "8080:80"
      - target: 443
        published: 8443
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := f.RestrictPortBindings("web", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected port restriction to change the file")
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if !strings.Contains(out, "127.0.0.1:8080:80") {
		t.Errorf("expected short-form port restricted\n%s", out)
	}
	if !strings.Contains(out, "target: 443") {
		t.Errorf("expected long-form mapping preserved\n%s", out)
	}
	if !strings.Contains(out, "127.0.0.1") || !strings.Contains(out, "8443") {
		t.Errorf("expected long-form host_ip restricted\n%s", out)
	}
}

func TestSetVolumeReadOnly_LongSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  web:
    image: nginx
    volumes:
      - type: bind
        source: /etc
        target: /host-etc
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := f.SetVolumeReadOnly("web", "/etc:/host-etc")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected volume to be marked read-only")
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "read_only:") {
		t.Errorf("expected read_only in file\n%s", string(data))
	}
}

func TestRemoveVolumeMount_LongSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	content := `services:
  agent:
    image: portainer/agent
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
      - type: volume
        source: data
        target: /data
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := f.RemoveVolumeMount("agent", "/var/run/docker.sock:/var/run/docker.sock")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected docker.sock mount to be removed")
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := string(data)
	if strings.Contains(out, "docker.sock") {
		t.Errorf("docker.sock mount should be removed\n%s", out)
	}
	if !strings.Contains(out, "target: /data") {
		t.Errorf("unrelated volume should remain\n%s", out)
	}
}
