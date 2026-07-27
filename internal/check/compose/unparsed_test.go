package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/platform"
)

// lsRunner scripts a host whose compose projects are the given files and
// which has no hand-started containers.
type lsRunner struct{ lsJSON string }

func (lsRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

func (r lsRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	joined := strings.Join(args, " ")
	switch {
	case name == "docker" && joined == "version --format {{.Server.Version}}":
		return []byte("27.0.3\n"), nil
	case name == "docker" && joined == "compose ls --all --format json":
		return []byte(r.lsJSON), nil
	case name == "docker" && joined == "ps --quiet --no-trunc":
		return []byte(""), nil
	}
	return nil, errors.New("unexpected command: " + name + " " + joined)
}

func writeCompose(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodStack = "services:\n  app:\n    image: myapp\n    privileged: true\n"

// A project docker knows about but whose file cannot be parsed is a stack
// this scan says nothing about. It used to be dropped with a bare `continue`
// and the domain reported ScanDone over the rest — the only place in the
// tree that let "I couldn't look" pass for "nothing there", which is
// precisely what scores a never-audited stack as clean.
func TestAnUnparseableProjectDegradesTheDomain(t *testing.T) {
	dir := t.TempDir()
	good := writeCompose(t, dir, "good.yml", goodStack)
	bad := writeCompose(t, dir, "bad.yml", "services:\n  app:\n    ports: [ {{{ ]\n")

	r := lsRunner{lsJSON: `[{"Name":"good","ConfigFiles":"` + good + `"},` +
		`{"Name":"bad","ConfigFiles":"` + bad + `"}]`}
	findings, err := (&Checker{}).Check(context.Background(), platform.Env{Runner: r})

	var partial *check.PartialError
	if !errors.As(err, &partial) {
		t.Fatalf("expected a PartialError, got %v", err)
	}
	if !strings.Contains(partial.Reason, bad) {
		t.Errorf("the reason should name the unparseable file: %q", partial.Reason)
	}
	if partial.Covered != 1 || partial.Total != 2 {
		t.Errorf("coverage = %d/%d, want 1/2", partial.Covered, partial.Total)
	}
	// The stack that did parse is still audited — partial means incomplete,
	// not failed.
	var sawPrivileged bool
	for _, f := range findings {
		if f.ID == "compose.ds001" {
			sawPrivileged = true
		}
	}
	if !sawPrivileged {
		t.Error("findings from the project that parsed must be kept")
	}
}

// The flag must stay quiet when every project parses, or Degraded stops
// meaning anything.
func TestAllProjectsParsingIsNotDegraded(t *testing.T) {
	dir := t.TempDir()
	good := writeCompose(t, dir, "good.yml", goodStack)

	r := lsRunner{lsJSON: `[{"Name":"good","ConfigFiles":"` + good + `"}]`}
	if _, err := (&Checker{}).Check(context.Background(), platform.Env{Runner: r}); err != nil {
		t.Errorf("a fully parseable host must not degrade: %v", err)
	}
}

// docker sometimes lists a project with no config file at all. There is
// nothing to audit and nothing we failed to read, so it must not degrade.
func TestAProjectWithNoConfigFileIsNotPartialCoverage(t *testing.T) {
	r := lsRunner{lsJSON: `[{"Name":"orphan","ConfigFiles":""}]`}
	if _, err := (&Checker{}).Check(context.Background(), platform.Env{Runner: r}); err != nil {
		t.Errorf("a project with no config file must not degrade: %v", err)
	}
}
