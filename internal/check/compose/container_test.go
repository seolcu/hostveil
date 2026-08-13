package compose

import (
	"context"
	"errors"
	compose "github.com/seolcu/hostveil/internal/compose"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// runRunner scripts a host with no compose projects and one hand-started
// container described by inspectJSON. ls overrides `docker compose ls` for
// the tests that need a project alongside the standalone container.
type runRunner struct {
	inspect string
	psErr   bool
	ls      string
}

func (runRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (r runRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case checktest.IsDockerProbe(name, args):
		return []byte("27.0.3\n"), nil
	case name == "docker" && joined == "compose ls --all --format json":
		if r.ls != "" {
			return []byte(r.ls), nil
		}
		return []byte(`[]`), nil
	case name == "docker" && joined == "ps --quiet --no-trunc":
		if r.psErr {
			return nil, errors.New("cannot connect to the Docker daemon")
		}
		return []byte("abc123\n"), nil
	case name == "docker" && len(args) > 0 && args[0] == "inspect":
		return []byte(r.inspect), nil
	}
	return nil, errors.New("unexpected command: " + name + " " + joined)
}

// The container the plan was written for: `docker run -d --privileged
// -p 6379:6379 -v /var/run/docker.sock:/var/run/docker.sock redis`.
const dangerousContainer = `[{
 "Name": "/cache",
 "Config": {"Image": "redis:alpine", "User": "", "Labels": {}},
 "HostConfig": {
  "Privileged": true,
  "NetworkMode": "bridge",
  "Binds": ["/var/run/docker.sock:/var/run/docker.sock:rw"],
  "PortBindings": {"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "6379"}]},
  "RestartPolicy": {"Name": "no"}
 }
}]`

func check2(t *testing.T, r platform.CommandRunner) []model.Finding {
	t.Helper()
	fs, err := New().Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func has(fs []model.Finding, id string) (model.Finding, bool) {
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

// Before this, every one of these produced nothing: the container is not in
// any compose file, so the checker never looked at it.
func TestStandaloneContainerIsAudited(t *testing.T) {
	fs := check2(t, runRunner{inspect: dangerousContainer})

	for _, id := range []string{
		"compose.ds001", // privileged
		"compose.ds016", // docker socket
		"compose.ds018", // datastore on 0.0.0.0
		"compose.ds006", // no no-new-privileges
		"compose.ds009", // runs as root
		"compose.ds008", // no restart policy
		"compose.ds012", // no healthcheck
		"compose.ds010", // no memory limit
	} {
		if _, ok := has(fs, id); !ok {
			t.Errorf("%s not reported for a hand-started container", id)
		}
	}
	if f, _ := has(fs, "compose.ds018"); f.Service != "cache" {
		t.Errorf("finding should be attributed to the container name, got %q", f.Service)
	}
}

// The rule that matters most: there is no file to edit, so no UI may offer a
// fix. Engine.classify takes the stricter of checker and registry, so the
// checker declaring Manual is what keeps a fix button from leading nowhere.
func TestStandaloneFindingsAreAlwaysManual(t *testing.T) {
	fs := check2(t, runRunner{inspect: dangerousContainer})
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if f.Remediation != model.RemediationManual {
			t.Errorf("%s is %v; a container with no compose file has nothing to edit", f.ID, f.Remediation)
		}
		if f.Evidence["managed_by"] != "docker run" {
			t.Errorf("%s does not record how the container is managed", f.ID)
		}
		if !strings.Contains(f.HowToFix, "docker run") {
			t.Errorf("%s how-to-fix does not explain why it cannot be automated: %q", f.ID, f.HowToFix)
		}
	}
}

// ds018 is registered as an Auto fix that edits a compose file. If the
// checker did not demote it, the registry would win and the fix would try to
// edit the empty path.
func TestExposedDatastoreIsNotAutoForAStandaloneContainer(t *testing.T) {
	fs := check2(t, runRunner{inspect: dangerousContainer})
	f, ok := has(fs, "compose.ds018")
	if !ok {
		t.Fatal("expected ds018")
	}
	if f.Remediation == model.RemediationAuto {
		t.Error("ds018 must not stay Auto: there is no compose file for the fix to write")
	}
	if f.Metadata["file"] != "" {
		t.Errorf("no compose file should be claimed, got %q", f.Metadata["file"])
	}
}

// A resolved environment merges the image's own ENV and anything an env_file
// supplied, so flagging it would accuse an operator who used a secrets file
// correctly — and tell them to do what they already did.
func TestResolvedEnvironmentIsNotScannedForSecrets(t *testing.T) {
	withSecret := `[{
	 "Name": "/app",
	 "Config": {"Image": "myapp", "Env": ["DB_PASSWORD=hunter2"], "Labels": {}},
	 "HostConfig": {"RestartPolicy": {"Name": "always"}}
	}]`
	fs := check2(t, runRunner{inspect: withSecret})
	if _, ok := has(fs, "compose.dr005"); ok {
		t.Error("dr005 must not fire on a resolved container environment")
	}
	if _, ok := has(fs, "compose.dr004"); ok {
		t.Error("dr004 has no meaning for a running container")
	}
}

// The daemon reports namespace modes and the root-filesystem flag directly,
// so `docker run --pid=host --ipc=host` is as visible as the compose keys —
// and a `--read-only` container must not be accused of a writable rootfs.
func TestHostNamespacesAuditedForStandaloneContainers(t *testing.T) {
	shared := `[{
	 "Name": "/monitor",
	 "Config": {"Image": "myapp", "User": "1000", "Labels": {}},
	 "HostConfig": {
	   "PidMode": "host",
	   "IpcMode": "host",
	   "ReadonlyRootfs": false,
	   "RestartPolicy": {"Name": "always"}
	 }
	}]`
	fs := check2(t, runRunner{inspect: shared})
	for _, id := range []string{"compose.ds020", "compose.ds021", "compose.ds022"} {
		if _, ok := has(fs, id); !ok {
			t.Errorf("%s not reported for a hand-started container", id)
		}
	}

	private := `[{
	 "Name": "/app",
	 "Config": {"Image": "myapp", "User": "1000", "Labels": {}},
	 "HostConfig": {
	   "PidMode": "private",
	   "IpcMode": "private",
	   "ReadonlyRootfs": true,
	   "RestartPolicy": {"Name": "always"}
	 }
	}]`
	fs = check2(t, runRunner{inspect: private})
	for _, id := range []string{"compose.ds020", "compose.ds021", "compose.ds022"} {
		if _, ok := has(fs, id); ok {
			t.Errorf("%s reported for a container with private namespaces and a read-only rootfs", id)
		}
	}
}

// Losing the ability to enumerate containers is a smaller blind spot than a
// failed scan, but it is still one: the domain covered compose only and has
// to say so rather than report a clean result.
func TestUninspectableContainersAreDegraded(t *testing.T) {
	_, err := New().Check(context.Background(), platform.Env{Runner: runRunner{psErr: true}})
	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
}

// Two blind spots at once must both be reported. The checker returned at the
// first one, so a host where container enumeration failed *and* a compose
// file would not parse was told only about the containers — and the unparsed
// stack, which the very next branch calls "the one thing a checker must never
// do" to report clean, went unmentioned.
func TestEveryCoverageGapIsReported(t *testing.T) {
	r := runRunner{
		psErr: true,
		ls:    `[{"Name":"broken","ConfigFiles":"/nonexistent/docker-compose.yml"}]`,
	}
	_, err := New().Check(context.Background(), platform.Env{Runner: r})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("want a PartialError so the axis reports Degraded, got %v", err)
	}
	if !strings.Contains(partial.Reason, "outside Compose") {
		t.Errorf("the failed container enumeration is missing from %q", partial.Reason)
	}
	if !strings.Contains(partial.Reason, "/nonexistent/docker-compose.yml") {
		t.Errorf("the unparsed compose file is missing from %q", partial.Reason)
	}
}

// A container that is fine produces nothing, so the new code path cannot
// become a source of noise on a well-run host.
func TestWellConfiguredStandaloneContainerIsClean(t *testing.T) {
	good := `[{
	 "Name": "/app",
	 "Config": {
	   "Image": "myapp:1.2",
	   "User": "1000:1000",
	   "Labels": {},
	   "Healthcheck": {"Test": ["CMD", "true"]}
	 },
	 "HostConfig": {
	   "Privileged": false,
	   "NetworkMode": "bridge",
	   "ReadonlyRootfs": true,
	   "SecurityOpt": ["no-new-privileges:true"],
	   "Binds": ["/srv/app/data:/data:rw"],
	   "Memory": 536870912,
	   "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
	   "RestartPolicy": {"Name": "unless-stopped"}
	 }
	}]`
	if fs := check2(t, runRunner{inspect: good}); len(fs) != 0 {
		t.Errorf("a correctly configured container should be clean, got %v", fs)
	}
}

// The demotion has to fill the field the interfaces actually read. A
// `docker run` container's findings are Manual for a reason that is specific
// to that container, not to the finding ID — so the registry cannot answer it
// and the checker has to.
func TestAContainerDemotionSaysWhyInTheFieldTheUIReads(t *testing.T) {
	fs := auditContainer(compose.Container{
		Name:    "db",
		Service: compose.Service{Ports: []compose.Port{{HostIP: "0.0.0.0", HostPort: "5432", ContainerPort: "5432", Published: true}}},
	})
	if len(fs) == 0 {
		t.Fatal("the fixture produced no findings")
	}
	for _, f := range fs {
		if f.Remediation != model.RemediationManual {
			t.Errorf("%s: remediation = %v, want Manual", f.ID, f.Remediation)
		}
		if f.WhyNoFix == "" {
			t.Errorf("%s: Manual with nothing in WhyNoFix — the panel that asks this question renders blank", f.ID)
		}
	}
}
