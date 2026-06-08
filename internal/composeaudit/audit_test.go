package composeaudit

import (
	"os"
	"testing"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func TestAuditProject_Privileged(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    privileged: true
  api:
    image: myapp
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds001") {
		t.Error("expected compose.ds001 for privileged: true")
	}
	if hasFindingForService(findings, "compose.ds001", "api") {
		t.Error("compose.ds001 should not apply to api service")
	}
}

func TestAuditProject_ReadOnly(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    read_only: true
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds002", "web") {
		t.Error("expected compose.ds002 for web (no read_only)")
	}
	if hasFindingForService(findings, "compose.ds002", "api") {
		t.Error("compose.ds002 should not apply to api (read_only: true)")
	}
}

func TestAuditProject_PIDModeHost(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    pid_mode: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds003") {
		t.Error("expected compose.ds003 for pid_mode: host")
	}
}

func TestAuditProject_IPCModeHost(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    ipc_mode: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds004") {
		t.Error("expected compose.ds004 for ipc_mode: host")
	}
}

func TestAuditProject_DangerousCapAdd(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    cap_add:
      - SYS_ADMIN
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds005") {
		t.Error("expected compose.ds005 for SYS_ADMIN cap_add")
	}
}

func TestAuditProject_NoNewPrivileges(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    security_opt:
      - no-new-privileges:true
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds006", "web") {
		t.Error("expected compose.ds006 for web (no no-new-privileges)")
	}
	if hasFindingForService(findings, "compose.ds006", "api") {
		t.Error("compose.ds006 should not apply to api (has no-new-privileges)")
	}
}

func TestAuditProject_UserNSHost(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    userns_mode: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds007") {
		t.Error("expected compose.ds007 for userns_mode: host")
	}
}

func TestAuditProject_RestartPolicy(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    restart: unless-stopped
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds008", "web") {
		t.Error("expected compose.ds008 for web (no restart)")
	}
	if hasFindingForService(findings, "compose.ds008", "api") {
		t.Error("compose.ds008 should not apply to api (restart: unless-stopped)")
	}
}

func TestAuditProject_UserRoot(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    user: "1000"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds009", "web") {
		t.Error("expected compose.ds009 for web (no user)")
	}
	if hasFindingForService(findings, "compose.ds009", "api") {
		t.Error("compose.ds009 should not apply to api (has user)")
	}
}

func TestAuditProject_MemoryLimit(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    deploy:
      resources:
        limits:
          memory: 256M
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds010", "web") {
		t.Error("expected compose.ds010 for web (no memory limit)")
	}
	if hasFindingForService(findings, "compose.ds010", "api") {
		t.Error("compose.ds010 should not apply to api (has memory limit)")
	}
}

func TestAuditProject_CPULimit(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: "0.5"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds011", "web") {
		t.Error("expected compose.ds011 for web (no CPU limit)")
	}
	if hasFindingForService(findings, "compose.ds011", "api") {
		t.Error("compose.ds011 should not apply to api (has CPU limit)")
	}
}

func TestAuditProject_Healthcheck(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
  api:
    image: myapp
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds012", "web") {
		t.Error("expected compose.ds012 for web (no healthcheck)")
	}
	if hasFindingForService(findings, "compose.ds012", "api") {
		t.Error("compose.ds012 should not apply to api (has healthcheck)")
	}
}

func TestAuditProject_NetworkModeHost(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    network_mode: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.dr001") {
		t.Error("expected compose.dr001 for network_mode: host")
	}
}

func TestAuditProject_PortBinding(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    ports:
      - "8080:80"
  api:
    image: myapp
    ports:
      - "127.0.0.1:9090:9090"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.dr002", "web") {
		t.Error("expected compose.dr002 for web (0.0.0.0 binding)")
	}
	if hasFindingForService(findings, "compose.dr002", "api") {
		t.Error("compose.dr002 should not apply to api (127.0.0.1 binding)")
	}
}

func TestAuditProject_VolumeRO(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    volumes:
      - ./data:/data
  api:
    image: myapp
    volumes:
      - ./data:/data:ro
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.dr003", "web") {
		t.Error("expected compose.dr003 for web (no :ro)")
	}
	if hasFindingForService(findings, "compose.dr003", "api") {
		t.Error("compose.dr003 should not apply to api (has :ro)")
	}
}

func TestAuditProject_SeccompUnconfined(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    security_opt:
      - seccomp:unconfined
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds014") {
		t.Error("expected compose.ds014 for seccomp:unconfined")
	}
}

func TestAuditProject_AppArmorUnconfined(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    security_opt:
      - apparmor:unconfined
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds015") {
		t.Error("expected compose.ds015 for apparmor:unconfined")
	}
}

func TestAuditProject_CleanService(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    read_only: true
    restart: unless-stopped
    user: "1000"
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: "1.0"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:80"
    volumes:
      - data:/data:ro
volumes:
  data:
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	findingIDs := make(map[string]bool)
	for _, f := range findings {
		findingIDs[f.ID] = true
	}
	for _, id := range []string{
		"compose.ds001", "compose.ds002", "compose.ds003", "compose.ds004",
		"compose.ds005", "compose.ds006", "compose.ds007", "compose.ds008",
		"compose.ds009", "compose.ds010", "compose.ds011", "compose.ds012",
		"compose.ds013", "compose.ds014", "compose.ds015",
		"compose.dr001", "compose.dr002", "compose.dr003",
	} {
		if findingIDs[id] {
			t.Errorf("clean service should not produce %s", id)
		}
	}
}

func TestAuditProject_EnvFileDetection(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    env_file: .env
`)
	findings := detectEnvFiles(f, "/tmp/compose.yml", "test")
	if !hasFinding(findings, "compose.dr004") {
		t.Error("expected compose.dr004 for env_file usage")
	}
}

func hasFinding(findings []domain.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func hasFindingForService(findings []domain.Finding, id, svc string) bool {
	for _, f := range findings {
		if f.ID == id && f.Service == svc {
			return true
		}
	}
	return false
}

func openCompose(t *testing.T, yaml string) *compose.File {
	t.Helper()
	f, err := os.CreateTemp("", "hostveil-test-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	c, err := compose.Open(f.Name())
	if err != nil {
		t.Fatalf("compose.Open: %v", err)
	}
	return c
}
