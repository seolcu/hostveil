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
    pid: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds003") {
		t.Error("expected compose.ds003 for pid: host")
	}
}

func TestAuditProject_IPCModeHost(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    ipc: host
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFinding(findings, "compose.ds004") {
		t.Error("expected compose.ds004 for ipc: host")
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

// TestAuditProject_PortBinding_LongSyntax is a regression test for a bug
// where checkPortBinding compared the ports node's Kind against the wrong
// numeric constant (3 instead of yaml.SequenceNode's actual value of 2),
// making the entire long-syntax branch dead code — long-form port mappings
// exposed on 0.0.0.0 were silently never flagged.
func TestAuditProject_PortBinding_LongSyntax(t *testing.T) {
	f := openCompose(t, `services:
  web:
    image: nginx
    ports:
      - target: 80
        published: "8080"
  api:
    image: myapp
    ports:
      - target: 9090
        published: "9090"
        host_ip: "127.0.0.1"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.dr002", "web") {
		t.Error("expected compose.dr002 for web (long-syntax, no host_ip defaults to 0.0.0.0)")
	}
	if hasFindingForService(findings, "compose.dr002", "api") {
		t.Error("compose.dr002 should not apply to api (long-syntax host_ip: 127.0.0.1)")
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
	// Regression: dr003 must carry the exact volume string in Evidence so the
	// fix (composeVolumeRO) can scope ":ro" to only the flagged mount instead
	// of appending it to every non-":ro" volume on the service.
	for _, fnd := range findings {
		if fnd.ID == "compose.dr003" && fnd.Service == "web" {
			if fnd.Evidence["volume"] != "./data:/data" {
				t.Errorf("dr003 Evidence[volume] = %q, want %q", fnd.Evidence["volume"], "./data:/data")
			}
		}
	}
}

func TestAuditProject_DockerSocketMount(t *testing.T) {
	f := openCompose(t, `services:
  portainer:
    image: portainer/portainer-ce
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  portainer-ro:
    image: portainer/portainer-ce
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
  alt-path:
    image: watchtower
    volumes:
      - /run/docker.sock:/var/run/docker.sock
  web:
    image: nginx
    volumes:
      - ./data:/data
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds016", "portainer") {
		t.Error("expected compose.ds016 for portainer (docker.sock mounted)")
	}
	if !hasFindingForService(findings, "compose.ds016", "portainer-ro") {
		t.Error("expected compose.ds016 for portainer-ro (:ro does not mitigate socket access)")
	}
	if !hasFindingForService(findings, "compose.ds016", "alt-path") {
		t.Error("expected compose.ds016 for alt-path (/run/docker.sock source)")
	}
	if hasFindingForService(findings, "compose.ds016", "web") {
		t.Error("compose.ds016 should not apply to web (no docker.sock mount)")
	}
	for _, fnd := range findings {
		if fnd.ID == "compose.ds016" {
			if fnd.Severity != domain.SeverityCritical {
				t.Errorf("compose.ds016 severity = %v, want Critical", fnd.Severity)
			}
			if fnd.Evidence["volume"] == "" {
				t.Error("compose.ds016 should carry the volume string in Evidence for the fix to remove")
			}
		}
	}
}

func TestAuditProject_SensitiveHostMount(t *testing.T) {
	f := openCompose(t, `services:
  etc-rw:
    image: busybox
    volumes:
      - /etc:/host-etc
  etc-ro:
    image: busybox
    volumes:
      - /etc:/host-etc:ro
  root-rw:
    image: busybox
    volumes:
      - /root:/host-root
  ssh-rw:
    image: busybox
    volumes:
      - /home/user/.ssh:/root/.ssh
  narrow:
    image: busybox
    volumes:
      - /etc/localtime:/etc/localtime
  home-subdir:
    image: busybox
    volumes:
      - /home/user/media:/media
  named-volume:
    image: busybox
    volumes:
      - data:/data
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds017", "etc-rw") {
		t.Error("expected compose.ds017 for etc-rw (/etc mounted read-write)")
	}
	if hasFindingForService(findings, "compose.ds017", "etc-ro") {
		t.Error("compose.ds017 should not apply to etc-ro (:ro mitigates)")
	}
	if !hasFindingForService(findings, "compose.ds017", "root-rw") {
		t.Error("expected compose.ds017 for root-rw (/root mounted read-write)")
	}
	if !hasFindingForService(findings, "compose.ds017", "ssh-rw") {
		t.Error("expected compose.ds017 for ssh-rw (.ssh directory mounted read-write)")
	}
	if hasFindingForService(findings, "compose.ds017", "narrow") {
		t.Error("compose.ds017 should not apply to narrow (/etc/localtime is not a sensitive root)")
	}
	if hasFindingForService(findings, "compose.ds017", "home-subdir") {
		t.Error("compose.ds017 should not apply to home-subdir (/home/user/media is a narrow subdirectory, not the /home root)")
	}
	if hasFindingForService(findings, "compose.ds017", "named-volume") {
		t.Error("compose.ds017 should not apply to named-volume (not a host path)")
	}
}

func TestAuditProject_UnauthenticatedDatastore(t *testing.T) {
	f := openCompose(t, `services:
  redis-exposed:
    image: redis:7.2-alpine
    ports:
      - "6379:6379"
  redis-localhost:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
  redis-internal:
    image: redis
  mongo-exposed:
    image: mongo:7.0
    ports:
      - "27017:27017"
  registry-path:
    image: docker.io/library/mongo:6
    ports:
      - "27018:27017"
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds018", "redis-exposed") {
		t.Error("expected compose.ds018 for redis-exposed (redis on 0.0.0.0)")
	}
	if hasFindingForService(findings, "compose.ds018", "redis-localhost") {
		t.Error("compose.ds018 should not apply to redis-localhost (bound to 127.0.0.1)")
	}
	if hasFindingForService(findings, "compose.ds018", "redis-internal") {
		t.Error("compose.ds018 should not apply to redis-internal (no port mapping at all)")
	}
	if !hasFindingForService(findings, "compose.ds018", "mongo-exposed") {
		t.Error("expected compose.ds018 for mongo-exposed (mongo on 0.0.0.0)")
	}
	if !hasFindingForService(findings, "compose.ds018", "registry-path") {
		t.Error("expected compose.ds018 for registry-path (docker.io/library/mongo should reduce to 'mongo')")
	}
	if hasFindingForService(findings, "compose.ds018", "web") {
		t.Error("compose.ds018 should not apply to web (nginx is not a datastore image)")
	}
	for _, fnd := range findings {
		if fnd.ID == "compose.ds018" && fnd.Severity != domain.SeverityCritical {
			t.Errorf("compose.ds018 severity = %v, want Critical", fnd.Severity)
		}
	}
}

func TestAuditProject_ExposedAdminPanel(t *testing.T) {
	f := openCompose(t, `services:
  portainer-exposed:
    image: portainer/portainer-ce:2.19
    ports:
      - "9000:9000"
  portainer-localhost:
    image: portainer/portainer-ce
    ports:
      - "127.0.0.1:9000:9000"
  phpmyadmin-exposed:
    image: phpmyadmin:5
    ports:
      - "8081:80"
  web:
    image: nginx
    ports:
      - "8080:80"
`)
	findings := auditProject(f, Project{Name: "test", ComposePath: "test.yml"})
	if !hasFindingForService(findings, "compose.ds019", "portainer-exposed") {
		t.Error("expected compose.ds019 for portainer-exposed (admin panel on 0.0.0.0)")
	}
	if hasFindingForService(findings, "compose.ds019", "portainer-localhost") {
		t.Error("compose.ds019 should not apply to portainer-localhost (bound to 127.0.0.1)")
	}
	if !hasFindingForService(findings, "compose.ds019", "phpmyadmin-exposed") {
		t.Error("expected compose.ds019 for phpmyadmin-exposed (admin panel on 0.0.0.0)")
	}
	if hasFindingForService(findings, "compose.ds019", "web") {
		t.Error("compose.ds019 should not apply to web (nginx is not an admin panel image)")
	}
	for _, fnd := range findings {
		if fnd.ID == "compose.ds019" && fnd.Severity != domain.SeverityHigh {
			t.Errorf("compose.ds019 severity = %v, want High", fnd.Severity)
		}
	}
}

func TestBaseImageName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"redis", "redis"},
		{"redis:7.2-alpine", "redis"},
		{"docker.io/library/mongo:6", "mongo"},
		{"ghcr.io/user/my-app:latest", "my-app"},
		{"portainer/portainer-ce:2.19.4", "portainer-ce"},
		{"myregistry.example.com:5000/redis:7", "redis"},
		{"redis@sha256:abcdef1234567890", "redis"},
		{"MONGO", "mongo"},
		{"", ""},
	}
	for _, c := range cases {
		if got := baseImageName(c.in); got != c.want {
			t.Errorf("baseImageName(%q) = %q, want %q", c.in, got, c.want)
		}
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
		"compose.ds016", "compose.ds017", "compose.ds018", "compose.ds019",
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
