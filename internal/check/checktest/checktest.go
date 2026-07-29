// Package checktest scripts the host a checker is tested against.
//
// Every checker reaches the OS through a platform.CommandRunner, so every
// checker's tests need a fake one. Nineteen were written by hand, and between
// them they had two shapes: a set of binaries that exist, and a map from a
// command with its arguments to what that command prints. What actually
// differed was which default each took — some listed the binaries present,
// some listed the ones missing — and how each spelled the argv it scripted.
//
// The spelling is the part that bites. A scripted argv that no longer matches
// what the caller runs does not fail the test. It falls through to the fake's
// unscripted-command error, and every checker reads a command that errored as
// a tool that did not answer — the same value a genuinely broken host
// produces. So a test written to cover the working case goes on passing while
// silently covering the opposite one. Script through Docker or Listeners
// below, or through platform's exported argv, rather than by writing the
// command out again.
//
// A Runner is safe to share between goroutines once built: the CVE checker
// scans images in parallel and platform.ScanCache calls it concurrently, and
// nothing here is written after construction.
package checktest

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// Runner is a platform.CommandRunner that answers from a script.
//
// The zero value is not useful; start from New. By default every binary is
// present and no command is scripted, which is the shape a checker meets when
// the tool exists but the test has not said what it prints.
type Runner struct {
	// only, when non-nil, is the complete set of binaries that exist. It and
	// absent are kept apart rather than folded into one map because the two
	// defaults answer different questions: Only says "this host has just
	// these", Without says "this host has everything but these", and a test
	// that means one and gets the other still runs.
	only    map[string]bool
	absent  map[string]bool
	outputs map[string]string
	errs    map[string]error
}

// New returns a runner on a host where every binary exists and no command has
// been scripted.
func New() *Runner {
	return &Runner{outputs: map[string]string{}, errs: map[string]error{}}
}

// Only makes these the only binaries that exist. Anything else fails
// LookPath, which is what a checker's Available gate reads.
func (r *Runner) Only(names ...string) *Runner {
	r.only = map[string]bool{}
	for _, n := range names {
		r.only[n] = true
	}
	return r
}

// Without removes binaries from a host that otherwise has everything.
func (r *Runner) Without(names ...string) *Runner {
	if r.absent == nil {
		r.absent = map[string]bool{}
	}
	for _, n := range names {
		r.absent[n] = true
	}
	return r
}

// Script makes argv print out. The argv is the command as the caller runs it,
// not a string to be split, so a scripted command that stops matching is a
// compile-time or an obvious runtime mismatch rather than a silent one.
func (r *Runner) Script(out string, argv ...string) *Runner {
	r.outputs[key(argv[0], argv[1:])] = out
	return r
}

// Fail makes argv return err. Distinct from leaving it unscripted only in
// that the error says what the test meant.
func (r *Runner) Fail(err error, argv ...string) *Runner {
	r.errs[key(argv[0], argv[1:])] = err
	return r
}

// Unscript removes a scripted command so that running it errors. That is the
// state a tool which is installed but refuses to answer leaves a checker in —
// `ufw status` without root, an iptables chain a non-root scan cannot read —
// and it is the one a checker must not confuse with an answer of "nothing".
func (r *Runner) Unscript(argv ...string) *Runner {
	delete(r.outputs, key(argv[0], argv[1:]))
	return r
}

// Outputs scripts several commands at once, keyed by the command and its
// arguments joined with single spaces. Convenient for a table of short
// commands; Script is the safer form for anything whose argv is defined
// elsewhere.
func (r *Runner) Outputs(m map[string]string) *Runner {
	for k, v := range m {
		r.outputs[k] = v
	}
	return r
}

// Docker scripts the daemon probe as answering with version, so
// platform.DockerReachable reports the daemon as up. The argv comes from
// platform, so a change to the probe reaches every test that uses this.
func (r *Runner) Docker(version string) *Runner {
	return r.Script(version+"\n", platform.DockerProbeArgv()...)
}

// DockerDown scripts the daemon probe as failing, which is the state a
// checker must not confuse with a host that has no containers.
func (r *Runner) DockerDown(reason string) *Runner {
	return r.Fail(errors.New(reason), platform.DockerProbeArgv()...)
}

// Listeners scripts `ss -tlnp` with the given rows.
func (r *Runner) Listeners(out string) *Runner {
	return r.Script(out, platform.ListenersArgv()...)
}

// Env wraps the runner in a scan environment, which is what a checker's
// Check and Available actually take.
func (r *Runner) Env() platform.Env { return platform.Env{Runner: r} }

// LookPath resolves a binary, honouring Only and Without.
func (r *Runner) LookPath(name string) (string, error) {
	if r.only != nil && !r.only[name] {
		return "", errors.New("not found: " + name)
	}
	if r.absent[name] {
		return "", errors.New("not found: " + name)
	}
	return "/usr/bin/" + name, nil
}

// Run answers from the script. An unscripted command is an error naming
// itself, so a test that mis-spells an argv reads the mismatch in the failure
// rather than having to infer it from a checker reporting an unreachable
// tool.
func (r *Runner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	k := key(name, args)
	if err, ok := r.errs[k]; ok {
		return nil, err
	}
	if out, ok := r.outputs[k]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("checktest: no output scripted for: " + k)
}

func key(name string, args []string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

// Also adds binaries to a host built with Only, for a test that layers one
// more tool onto a shared fixture rather than restating the whole set.
func (r *Runner) Also(names ...string) *Runner {
	if r.only == nil {
		r.only = map[string]bool{}
	}
	for _, n := range names {
		r.only[n] = true
		delete(r.absent, n)
	}
	return r
}

// ListenersFail scripts `ss` as failing. A checker that cannot enumerate
// listening sockets has covered none of its ground, which is a different
// answer from a host with nothing listening.
func (r *Runner) ListenersFail(err error) *Runner {
	return r.Fail(err, platform.ListenersArgv()...)
}

// IsDockerProbe reports whether a call is platform.DockerReachable's probe.
//
// For the fakes that cannot be a plain command-to-output map — the ones
// scripting `docker inspect <ids...>` or recording a Trivy argv whose last
// element is the image — so that they too stop spelling the probe out.
func IsDockerProbe(name string, args []string) bool {
	return key(name, args) == key(platform.DockerProbeArgv()[0], platform.DockerProbeArgv()[1:])
}

// ComposeProjects scripts a reachable Docker daemon whose compose projects
// are the given name → config-file pairs, and which has no containers started
// outside them.
//
// Three packages built this same host by hand, each writing the `docker
// compose ls` JSON out as a string literal. The projects are emitted in name
// order so a fixture built from a map does not vary between runs.
func ComposeProjects(projects map[string]string) *Runner {
	names := make([]string, 0, len(projects))
	for n := range projects {
		names = append(names, n)
	}
	sort.Strings(names)

	rows := make([]composeLS, 0, len(names))
	for _, n := range names {
		rows = append(rows, composeLS{Name: n, ConfigFiles: projects[n]})
	}
	ls, err := json.Marshal(rows)
	if err != nil { // unreachable: the rows are two strings
		panic("checktest: " + err.Error())
	}
	return New().Docker("27.0.3").
		Script(string(ls), "docker", "compose", "ls", "--all", "--format", "json").
		Script("", "docker", "ps", "--quiet", "--no-trunc")
}

// composeLS is the shape `docker compose ls --all --format json` prints.
type composeLS struct {
	Name        string
	ConfigFiles string
}
