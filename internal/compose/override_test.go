package compose

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
)

// `docker compose up` reads docker-compose.override.yml with no flag asked
// for — it is the documented way to layer local changes — and `docker compose
// -f a.yml -f b.yml` is the standard production pattern. docker reports every
// one of them in ConfigFiles as a comma-separated list, and hostveil read
// only the first.
//
// That is not a partial view, it is a wrong one, and in the dangerous
// direction. Compose *appends* port mappings rather than replacing them, as
// docker itself shows for exactly this pair:
//
//	ports:
//	  - {host_ip: 127.0.0.1, target: 6379, published: "6379"}
//	  - {target: 6379, published: "6379"}
//
// So the effective state is published on every interface. Reading the base
// file alone sees the loopback binding, finds nothing, and reports an exposed
// datastore as clean.
func TestAnOverrideFileChangesWhatIsExposed(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "docker-compose.yml")
	over := filepath.Join(dir, "docker-compose.override.yml")
	write(t, base, "services:\n  cache:\n    image: redis:7\n    ports:\n      - \"127.0.0.1:6379:6379\"\n")
	write(t, over, "services:\n  cache:\n    ports:\n      - \"6379:6379\"\n")

	r := checktest.New().Docker("27.0.3").
		Script(`[{"Name":"proj","ConfigFiles":"`+base+`,`+over+`"}]`,
			"docker", "compose", "ls", "--all", "--format", "json").
		// What docker answers when asked for the merged configuration.
		Script("name: proj\nservices:\n  cache:\n    image: redis:7\n    ports:\n"+
			"      - mode: ingress\n        host_ip: 127.0.0.1\n        target: 6379\n        published: \"6379\"\n        protocol: tcp\n"+
			"      - mode: ingress\n        target: 6379\n        published: \"6379\"\n        protocol: tcp\n",
			"docker", "compose", "-f", base, "-f", over, "config")

	projects, skipped, err := Discover(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nothing should be skipped: %v", skipped)
	}
	if len(projects) != 1 {
		t.Fatalf("got %d projects", len(projects))
	}
	svc := projects[0].Services["cache"]
	var exposed bool
	for _, p := range svc.Ports {
		if p.ExposedOnAllInterfaces() {
			exposed = true
		}
	}
	if !exposed {
		t.Errorf("the override publishes this datastore on every interface and it was not seen: %+v", svc.Ports)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// realMergedConfig is `docker compose -f base.yml -f override.yml config`
// copied verbatim off a running Docker 27, for a base that binds redis to
// loopback and mounts ./data, and an override that publishes the port and adds
// privileged.
//
// Fixtures for this path have to come from docker rather than be written by
// hand, because `config` does not echo the input back — it normalizes. Ports
// become long-form maps, volumes become {type, source, target} with the
// relative source resolved to an absolute path, and a `networks` block appears
// that no input file mentioned. A hand-written fixture would agree with
// whatever the parser happened to do.
const realMergedConfig = `name: proj
services:
  cache:
    image: redis:7
    networks:
      default: null
    ports:
      - mode: ingress
        host_ip: 127.0.0.1
        target: 6379
        published: "6379"
        protocol: tcp
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
    privileged: true
    volumes:
      - type: bind
        source: /srv/proj/data
        target: /data
        bind: {}
  web:
    image: nginx
    networks:
      default: null
    ports:
      - mode: ingress
        target: 80
        published: "8080"
        protocol: tcp
networks:
  default:
    name: proj_default
`

func TestParsesWhatDockerActuallyEmits(t *testing.T) {
	proj, err := Parse("/srv/proj/docker-compose.yml", []byte(realMergedConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(proj.Services) != 2 {
		t.Fatalf("services = %v", proj.Services)
	}

	cache := proj.Services["cache"]
	if !cache.Privileged {
		t.Error("privileged came from the override and must survive the merge")
	}
	var loopback, everywhere int
	for _, p := range cache.Ports {
		if p.ExposedOnAllInterfaces() {
			everywhere++
		} else if p.Published {
			loopback++
		}
	}
	// Both, because compose appends rather than replaces — and it is the
	// second one that makes this a finding.
	if everywhere != 1 || loopback != 1 {
		t.Errorf("ports = %+v, want one loopback and one on every interface", cache.Ports)
	}
	// The long volume form, with the relative source already resolved. Reading
	// the raw file would have given "./data" and no idea what it points at.
	if len(cache.Volumes) != 1 || cache.Volumes[0].Target != "/data" {
		t.Errorf("volumes = %+v", cache.Volumes)
	}
	if p := proj.Services["web"].Ports; len(p) != 1 || !p[0].ExposedOnAllInterfaces() || p[0].HostPort != "8080" {
		t.Errorf("web ports = %+v", p)
	}
}

// When docker will not answer and there is more than one file, the merge is
// the whole question. Guessing at it would put back the wrong answer this
// exists to remove, so the project becomes ground the scan did not cover.
func TestAnUnresolvableMergeIsReportedNotGuessed(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "docker-compose.yml")
	over := filepath.Join(dir, "docker-compose.override.yml")
	write(t, base, "services:\n  cache:\n    image: redis:7\n    ports:\n      - \"127.0.0.1:6379:6379\"\n")
	write(t, over, "services:\n  cache:\n    ports:\n      - \"6379:6379\"\n")

	// `config` is left unscripted, so it errors the way it does on an unset
	// variable a mapping demands or a compose too old for the flags.
	r := checktest.New().Docker("27.0.3").
		Script(`[{"Name":"proj","ConfigFiles":"`+base+`,`+over+`"}]`,
			"docker", "compose", "ls", "--all", "--format", "json")

	projects, skipped, err := Discover(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 0 {
		t.Errorf("a project whose merge could not be resolved must not be audited from one file: %+v", projects)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %v, want the project reported as uncovered", skipped)
	}
}

// One file has no merge to lose, so a docker that will not answer costs
// nothing: that file is the project. This is the path every ordinary
// single-file host takes when its compose is too old for `config`.
func TestASingleFileStillParsesWithoutDocker(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "docker-compose.yml")
	write(t, base, "services:\n  cache:\n    image: redis:7\n    ports:\n      - \"6379:6379\"\n")

	r := checktest.New().Docker("27.0.3").
		Script(`[{"Name":"proj","ConfigFiles":"`+base+`"}]`,
			"docker", "compose", "ls", "--all", "--format", "json")

	projects, skipped, err := Discover(context.Background(), r)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("err=%v skipped=%v", err, skipped)
	}
	if len(projects) != 1 || !projects[0].Services["cache"].Ports[0].ExposedOnAllInterfaces() {
		t.Errorf("projects = %+v", projects)
	}
}
