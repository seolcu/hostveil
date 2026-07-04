package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

const testComposeYAML = `services:
  web:
    image: nginx:latest
    privileged: true
    ports:
      - "80:80"
    cap_add:
      - SYS_ADMIN
    volumes:
      - ./data:/var/lib/data

  db:
    image: postgres:15
    restart: always
`

func writeTestCompose(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testContext(t *testing.T, composePath, service string) Context {
	t.Helper()
	return Context{
		Finding: &domain.Finding{
			Evidence: map[string]string{},
			Metadata: map[string]string{
				"compose_path": composePath,
			},
			Service: service,
		},
		Log: func(s string, args ...interface{}) {},
	}
}

func TestComposeEdit(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	if err := composeEdit(ctx, "read_only", true); err != nil {
		t.Fatalf("composeEdit: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "read_only: true") {
		t.Errorf("compose file should contain read_only: true\n%s", string(data))
	}
}

func TestComposeEdit_AllServices(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "")
	if err := composeEdit(ctx, "read_only", true); err != nil {
		t.Fatalf("composeEdit: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "read_only: true") {
		t.Errorf("compose file should contain read_only: true\n%s", string(data))
	}
}

func TestComposeDel(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	if err := composeDel(ctx, "privileged"); err != nil {
		t.Fatalf("composeDel: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "privileged: true") {
		t.Errorf("compose file should not contain privileged\n%s", string(data))
	}
}

func TestComposeDrop(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	if err := composeDrop(ctx, "cap_add", "SYS_ADMIN"); err != nil {
		t.Fatalf("composeDrop: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SYS_ADMIN") {
		t.Errorf("compose file should not contain SYS_ADMIN\n%s", string(data))
	}
}

func TestComposePortRestrict(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	if err := composePortRestrict(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("composePortRestrict: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "127.0.0.1:80") {
		t.Errorf("compose file should contain 127.0.0.1:80\n%s", string(data))
	}
}

func TestComposeVolumeRO(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	ctx.Finding.Evidence["volume"] = "./data:/var/lib/data"
	if err := composeVolumeRO(ctx); err != nil {
		t.Fatalf("composeVolumeRO: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), ":ro") {
		t.Errorf("compose file should contain :ro\n%s", string(data))
	}
}

func TestComposeDropVolume(t *testing.T) {
	yamlContent := `services:
  portainer:
    image: portainer/portainer-ce
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - portainer_data:/data
`
	path := writeTestCompose(t, yamlContent)
	ctx := testContext(t, path, "portainer")
	ctx.Finding.Evidence["volume"] = "/var/run/docker.sock:/var/run/docker.sock"
	if err := composeDropVolume(ctx); err != nil {
		t.Fatalf("composeDropVolume: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "docker.sock") {
		t.Errorf("compose file should not contain docker.sock after fix\n%s", string(data))
	}
	if !strings.Contains(string(data), "portainer_data:/data") {
		t.Errorf("compose file should still contain the unrelated named volume\n%s", string(data))
	}
}

func TestComposeDropVolume_NoEvidence(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	if err := composeDropVolume(ctx); err == nil {
		t.Error("composeDropVolume should error when Evidence[\"volume\"] is empty")
	}
}

func TestComposeAppendSecurityOpt_PreservesExisting(t *testing.T) {
	yamlContent := `services:
  web:
    image: nginx
    security_opt:
      - seccomp:unconfined
`
	path := writeTestCompose(t, yamlContent)
	ctx := testContext(t, path, "web")
	if err := composeAppendSecurityOpt(ctx); err != nil {
		t.Fatalf("composeAppendSecurityOpt: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "seccomp:unconfined") {
		t.Errorf("expected existing security_opt preserved\n%s", content)
	}
	if !strings.Contains(content, "no-new-privileges:true") {
		t.Errorf("expected no-new-privileges appended\n%s", content)
	}
}

func TestComposeEnvToVariable(t *testing.T) {
	yamlContent := `services:
  db:
    image: postgres:15
    environment:
      DB_PASSWORD: changeme
`
	path := writeTestCompose(t, yamlContent)
	ctx := testContext(t, path, "db")
	ctx.Finding.Evidence["env_key"] = "DB_PASSWORD"
	if err := composeEnvToVariable(ctx); err != nil {
		t.Fatalf("composeEnvToVariable: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "${DB_PASSWORD}") {
		t.Errorf("expected ${DB_PASSWORD} placeholder\n%s", string(data))
	}
}

func TestOpenComposeFile_MissingPath(t *testing.T) {
	ctx := Context{
		Finding: &domain.Finding{
			Metadata: map[string]string{},
		},
	}
	_, err := openComposeFile(ctx)
	if err == nil {
		t.Error("openComposeFile with empty compose_path should return error")
	}
}

func TestTargetServices_Specific(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "web")
	f, err := openComposeFile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 1 || svcs[0] != "web" {
		t.Errorf("targetServices(web) = %v, want [web]", svcs)
	}
}

func TestTargetServices_All(t *testing.T) {
	path := writeTestCompose(t, testComposeYAML)
	ctx := testContext(t, path, "")
	f, err := openComposeFile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := targetServices(f, ctx.Finding.Service)
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 {
		t.Errorf("targetServices(all) = %v, want [web, db]", svcs)
	}
}

func TestRestrictPort(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		bind    string
		want    string
		changed bool
	}{
		// Short form: HOST:CONTAINER
		{"short form", "8080:80", "127.0.0.1", "127.0.0.1:8080:80", true},
		// Long form: BIND_IP:HOST:CONTAINER (the actual bug case)
		{"long form wildcard", "0.0.0.0:8080:80", "127.0.0.1", "127.0.0.1:8080:80", true},
		{"long form loopback", "127.0.0.1:8080:80", "127.0.0.1", "127.0.0.1:8080:80", true},
		// With protocol suffix
		{"short with tcp", "8080:80/tcp", "127.0.0.1", "127.0.0.1:8080:80/tcp", true},
		{"long with tcp", "0.0.0.0:8080:80/tcp", "127.0.0.1", "127.0.0.1:8080:80/tcp", true},
		// Container port only — no host binding, no change
		{"container only", "80", "127.0.0.1", "80", false},
		// Short-form range — change (prepend bind)
		{"short range", "3000-3005:3000-3005", "127.0.0.1", "127.0.0.1:3000-3005:3000-3005", true},
		// Long-form range with wildcard IP — leave alone (range handling deferred)
		{"long range wildcard", "0.0.0.0:3000-3005:3000-3005", "127.0.0.1", "0.0.0.0:3000-3005:3000-3005", false},
		// Empty
		{"empty", "", "127.0.0.1", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := restrictPort(tt.input, tt.bind)
			if got != tt.want || changed != tt.changed {
				t.Errorf("restrictPort(%q, %q) = (%q, %v), want (%q, %v)",
					tt.input, tt.bind, got, changed, tt.want, tt.changed)
			}
		})
	}
}

// TestComposePortRestrict_LongForm is a regression test for the dr002 bug
// where port mappings in long form (BIND_IP:HOST:CONTAINER) were silently
// ignored by the regex, making the fix a no-op even though it reported
// success.
func TestComposePortRestrict_LongForm(t *testing.T) {
	const yml = `services:
  web:
    image: nginx:alpine
    ports:
      - 0.0.0.0:8080:80
`
	path := writeTestCompose(t, yml)
	ctx := testContext(t, path, "web")
	if err := composePortRestrict(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("composePortRestrict: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "127.0.0.1:8080:80") {
		t.Errorf("compose file should contain 127.0.0.1:8080:80 (regression! long-form port was not restricted)\n%s", content)
	}
	if strings.Contains(content, "0.0.0.0:8080:80") {
		t.Errorf("compose file should not contain 0.0.0.0:8080:80\n%s", content)
	}
}
