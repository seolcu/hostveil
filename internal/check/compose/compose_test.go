package compose

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// findingsFor parses a compose fragment and audits its single service,
// returning the finding IDs produced.
func findingsFor(t *testing.T, yaml string) map[string]model.Finding {
	t.Helper()
	proj, err := compose.Parse("test.yml", []byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byID := map[string]model.Finding{}
	for _, name := range sortedServiceNames(proj) {
		for _, f := range auditService(proj.Services[name]) {
			if f.Validate() != nil {
				t.Errorf("rule produced invalid finding: %+v", f)
			}
			byID[f.ID] = f
		}
	}
	return byID
}

func TestDetectsCriticalMisconfigurations(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "docker socket",
			yaml: `services:
  app:
    image: myapp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro`,
			want: "compose.ds016",
		},
		{
			name: "exposed redis",
			yaml: `services:
  cache:
    image: redis:7
    ports:
      - "6379:6379"`,
			want: "compose.ds018",
		},
		{
			name: "privileged",
			yaml: `services:
  app:
    image: myapp
    privileged: true`,
			want: "compose.ds001",
		},
		{
			name: "host network",
			yaml: `services:
  app:
    image: myapp
    network_mode: host`,
			want: "compose.dr001",
		},
		{
			name: "sensitive host mount rw",
			yaml: `services:
  app:
    image: myapp
    volumes:
      - /etc:/host/etc`,
			want: "compose.ds017",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := findingsFor(t, tc.yaml)
			if _, ok := got[tc.want]; !ok {
				t.Errorf("expected %s, got %v", tc.want, keys(got))
			}
		})
	}
}

func TestLoopbackBoundPortIsNotFlagged(t *testing.T) {
	got := findingsFor(t, `services:
  cache:
    image: redis:7
    ports:
      - "127.0.0.1:6379:6379"`)
	if _, ok := got["compose.ds018"]; ok {
		t.Error("loopback-bound datastore should not be flagged as exposed")
	}
}

func TestHardenedServiceIsClean(t *testing.T) {
	got := findingsFor(t, `services:
  app:
    image: myapp:1.2.3
    read_only: true
    restart: unless-stopped
    user: "1000:1000"
    mem_limit: 256m
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "true"]
    ports:
      - "127.0.0.1:8080:80"`)
	// Only allow the low-severity "no healthcheck"? It has one. Should be clean.
	if len(got) != 0 {
		t.Errorf("hardened service produced findings: %v", keys(got))
	}
}

func TestInlineSecretDetected(t *testing.T) {
	got := findingsFor(t, `services:
  db:
    image: myapp
    environment:
      POSTGRES_PASSWORD: hunter2secret
      OTHER_VAR: ${FROM_ENV}`)
	f, ok := got["compose.dr005"]
	if !ok {
		t.Fatalf("expected inline secret finding, got %v", keys(got))
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("inline secret severity = %v, want high", f.Severity)
	}
}

func TestReferencedSecretNotFlagged(t *testing.T) {
	got := findingsFor(t, `services:
  db:
    image: myapp
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}`)
	if _, ok := got["compose.dr005"]; ok {
		t.Error("a ${VAR} reference should not be flagged as a hardcoded secret")
	}
}

func TestImageBasename(t *testing.T) {
	cases := map[string]string{
		"redis":                        "redis",
		"redis:7":                      "redis",
		"docker.io/library/redis":      "redis",
		"docker.io/library/redis:7":    "redis",
		"ghcr.io/user/app:v1.2":        "app",
		"registry:5000/team/db:latest": "db",
	}
	for in, want := range cases {
		if got := imageBasename(in); got != want {
			t.Errorf("imageBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

func keys(m map[string]model.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestLongFormPortParsing covers the long-syntax port mapping.
func TestLongFormPortParsing(t *testing.T) {
	got := findingsFor(t, `services:
  cache:
    image: redis
    ports:
      - target: 6379
        published: "6379"
        host_ip: 0.0.0.0`)
	if _, ok := got["compose.ds018"]; !ok {
		t.Errorf("long-form 0.0.0.0 port should flag exposed datastore, got %v", keys(got))
	}
	if !strings.HasPrefix("compose.ds018", "compose.") {
		t.Fatal("sanity")
	}
}

// TestEmittedFindingsCarryWhatTheirFixNeeds catches a whole class of silent
// failure. classify swallows a fix-builder error and demotes the finding to
// Manual, so a checker that forgets a piece of evidence its builder reads
// produces a finding that looks correct, scores correctly, and simply never
// offers the fix that is registered for it. ds019 shipped that way: it
// recorded the image but not the host port that buildBindLoopback requires.
func TestEmittedFindingsCarryWhatTheirFixNeeds(t *testing.T) {
	// One service per rule that has a registered fix.
	yaml := `services:
  panel:
    image: portainer/portainer-ce
    ports:
      - "9000:9000"
  cache:
    image: redis
    ports:
      - "6379:6379"
  app:
    image: myapp
    ports:
      - "8080:80"
`
	proj, err := compose.Parse("/tmp/docker-compose.yml", []byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	registry := fix.Default()
	var checked int
	for _, name := range sortedServiceNames(proj) {
		for _, f := range auditService(proj.Services[name]) {
			// Mirror what Checker.Check attaches before the engine sees it.
			f.Metadata = mergeMeta(f.Metadata, map[string]string{
				"file":    "/tmp/docker-compose.yml",
				"service": name,
			})
			if !registry.Has(f.ID) {
				continue
			}
			checked++
			if _, ok, err := registry.Build(f); err != nil || !ok {
				t.Errorf("%s (%s): a fix is registered but will not build, so classify "+
					"silently demotes it to Manual: ok=%v err=%v", f.ID, name, ok, err)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no findings with registered fixes were exercised — the check is vacuous")
	}
}
