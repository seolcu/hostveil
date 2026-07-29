package checktest

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/seolcu/hostveil/internal/platform"
)

// The trap this package has to get right. The nineteen fakes it replaced took
// two opposite defaults — some listed the binaries present, some the ones
// missing — and a fixture that means one and silently gets the other still
// runs. It just tests a different host than the one it names.
func TestOnlyAndWithoutAreOppositeDefaults(t *testing.T) {
	if _, err := New().LookPath("anything"); err != nil {
		t.Errorf("the default host has every binary: %v", err)
	}
	if _, err := New().Only("ufw").LookPath("nft"); err == nil {
		t.Error("Only(ufw) must not leave nft on the host")
	}
	if _, err := New().Only("ufw").LookPath("ufw"); err != nil {
		t.Errorf("Only(ufw) must leave ufw: %v", err)
	}
	// A host with no tooling at all, which several checkers read as a
	// confident "absent" rather than as "could not look".
	if _, err := New().Only().LookPath("ufw"); err == nil {
		t.Error("Only() with no names is a host with no binaries")
	}
	if _, err := New().Without("ss").LookPath("ss"); err == nil {
		t.Error("Without(ss) must remove ss")
	}
	if _, err := New().Without("ss").LookPath("ufw"); err != nil {
		t.Errorf("Without(ss) leaves everything else: %v", err)
	}
	if _, err := New().Only("ufw").Also("nft").LookPath("nft"); err != nil {
		t.Errorf("Also must extend the Only set: %v", err)
	}
}

// An unscripted command errors rather than returning empty output. The
// distinction is the whole reason the checkers have a Degraded state: empty
// output is an answer, and a command that would not run is not.
func TestUnscriptedCommandErrors(t *testing.T) {
	r := New().Script("hello\n", "echo", "hello")
	out, err := r.Run(context.Background(), "echo", "hello")
	if err != nil || string(out) != "hello\n" {
		t.Fatalf("scripted command: %q, %v", out, err)
	}
	if _, err := r.Run(context.Background(), "echo", "goodbye"); err == nil {
		t.Error("an unscripted command must error, not return nothing")
	}
	if _, err := r.Unscript("echo", "hello").Run(context.Background(), "echo", "hello"); err == nil {
		t.Error("Unscript must put the command back to erroring")
	}
}

// The reason Docker and Listeners exist at all: the argv comes from platform,
// so a change to the probe reaches every fixture. A test that scripted its own
// copy would keep passing against the stale spelling, because the fake's miss
// and a daemon that will not answer produce the same value.
func TestScriptedProbesUsePlatformsArgv(t *testing.T) {
	r := New().Docker("27.0.3")
	if ok, reason := platform.DockerReachable(context.Background(), r); !ok {
		t.Errorf("Docker() did not satisfy the real probe: %q", reason)
	}
	if ok, _ := platform.DockerReachable(context.Background(), New().DockerDown("permission denied")); ok {
		t.Error("DockerDown() must make the real probe report the daemon unreachable")
	}
	if !IsDockerProbe("docker", platform.DockerProbeArgv()[1:]) {
		t.Error("IsDockerProbe does not recognize platform's own argv")
	}
	if IsDockerProbe("docker", []string{"ps"}) {
		t.Error("IsDockerProbe matched something that is not the probe")
	}

	ls, err := platform.Listeners(context.Background(),
		New().Listeners(`LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=1,fd=6))`))
	if err != nil {
		t.Fatalf("Listeners() did not satisfy the real caller: %v", err)
	}
	if len(ls) != 1 {
		t.Errorf("parsed %d listeners, want 1", len(ls))
	}
	if _, err := platform.Listeners(context.Background(), New()); err == nil {
		t.Error("an unscripted ss must surface as an error, not as no listeners")
	}
}

// A fixture built from a map must not vary between runs, or a failure is
// reproducible only sometimes.
func TestComposeProjectsIsOrdered(t *testing.T) {
	r := ComposeProjects(map[string]string{"zeta": "/z.yml", "alpha": "/a.yml"})
	out, err := r.Run(context.Background(), "docker", "compose", "ls", "--all", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []composeLS
	if err := json.Unmarshal(out, &rows); err != nil {
		t.Fatalf("not the JSON docker prints: %v", err)
	}
	if len(rows) != 2 || rows[0].Name != "alpha" || rows[1].Name != "zeta" {
		t.Errorf("projects out of order: %+v", rows)
	}
	if rows[0].ConfigFiles != "/a.yml" {
		t.Errorf("config file lost: %+v", rows[0])
	}
	// The daemon has to answer, or every checker skips before reading any of
	// this.
	if ok, _ := platform.DockerReachable(context.Background(), r); !ok {
		t.Error("ComposeProjects must script a reachable daemon")
	}
}

var _ platform.CommandRunner = (*Runner)(nil)
