package platform

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type scriptRunner struct {
	out     string
	err     error
	missing bool
}

func (s scriptRunner) LookPath(name string) (string, error) {
	if s.missing {
		return "", errors.New("not found")
	}
	return "/usr/bin/" + name, nil
}

func (s scriptRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(s.out), s.err
}

func trace(t *testing.T, inner CommandRunner, do func(CommandRunner)) string {
	t.Helper()
	var buf bytes.Buffer
	do(NewTraceRunner(inner, &buf))
	return buf.String()
}

// A failing command is the whole reason this exists: the domain Reason
// string collapses stderr to one truncated line, so without a trace there
// was no way to answer "it says my firewall is inactive, but it isn't".
func TestTraceRecordsCommandsAndFailures(t *testing.T) {
	got := trace(t, scriptRunner{err: errors.New("exit status 1: permission denied")}, func(r CommandRunner) {
		_, _ = r.Run(context.Background(), "ufw", "status")
	})
	if !strings.Contains(got, "ufw status") {
		t.Errorf("the trace should name the command: %q", got)
	}
	if !strings.Contains(got, "FAILED") || !strings.Contains(got, "permission denied") {
		t.Errorf("the trace should carry the failure: %q", got)
	}
}

// Half of every "my domain was skipped" report is a lookup: a binary in
// /usr/sbin that is not on a non-login PATH looks exactly like one that is
// not installed.
func TestTraceRecordsLookups(t *testing.T) {
	found := trace(t, scriptRunner{}, func(r CommandRunner) { _, _ = r.LookPath("docker") })
	if !strings.Contains(found, "/usr/bin/docker") {
		t.Errorf("a successful lookup should name the path: %q", found)
	}
	missing := trace(t, scriptRunner{missing: true}, func(r CommandRunner) { _, _ = r.LookPath("trivy") })
	if !strings.Contains(missing, "not found") {
		t.Errorf("a failed lookup should say so: %q", missing)
	}
}

// Command output routinely contains environment variables — `docker
// inspect` reports the resolved environment of every container. A trace an
// operator pastes into a bug report must not be a credential leak.
func TestTraceNeverLogsCommandOutput(t *testing.T) {
	const secret = "AWS_SECRET_ACCESS_KEY=hunter2"
	got := trace(t, scriptRunner{out: secret}, func(r CommandRunner) {
		_, _ = r.Run(context.Background(), "docker", "inspect", "abc")
	})
	if strings.Contains(got, "hunter2") || strings.Contains(got, "AWS_SECRET") {
		t.Fatalf("the trace leaked command output: %q", got)
	}
	if !strings.Contains(got, "bytes") {
		t.Errorf("the size should still be reported: %q", got)
	}
}

// Arguments must survive a round trip through a shell, or the trace is half
// a diagnostic — nobody can rerun the command it describes.
func TestTraceQuotesArgumentsThatNeedIt(t *testing.T) {
	got := trace(t, scriptRunner{}, func(r CommandRunner) {
		_, _ = r.Run(context.Background(), "docker", "version", "--format", "{{.Server.Version}}")
	})
	if !strings.Contains(got, `'{{.Server.Version}}'`) {
		t.Errorf("braces need quoting to be re-runnable: %q", got)
	}
}

// Checkers all run at once, so unsynchronised writes would interleave two
// commands into one unreadable line.
func TestTraceLinesAreNotInterleaved(t *testing.T) {
	var buf bytes.Buffer
	r := NewTraceRunner(scriptRunner{}, &buf)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Run(context.Background(), "docker", "ps")
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("got %d lines from 50 commands", len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "hostveil[trace] run  docker ps") {
			t.Fatalf("a line was torn: %q", l)
		}
	}
}
