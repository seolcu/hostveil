package platform

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// countingRunner records how many times each command actually reached the
// host, and can be held mid-call to force overlapping requests.
type countingRunner struct {
	runs      atomic.Int64
	lookups   atomic.Int64
	release   chan struct{} // when non-nil, Run blocks until it is closed
	entered   chan struct{} // closed once the first Run has begun
	enterOnce sync.Once
	failWith  error
	perAnswer map[string]string
}

func (c *countingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	c.runs.Add(1)
	if c.entered != nil {
		c.enterOnce.Do(func() { close(c.entered) })
	}
	if c.release != nil {
		<-c.release
	}
	if c.failWith != nil {
		return nil, c.failWith
	}
	return []byte(c.perAnswer[name+" "+strings.Join(args, " ")]), nil
}

func (c *countingRunner) LookPath(name string) (string, error) {
	c.lookups.Add(1)
	if c.failWith != nil {
		return "", c.failWith
	}
	return "/usr/bin/" + name, nil
}

func TestScanCacheRunsEachCommandOnce(t *testing.T) {
	inner := &countingRunner{perAnswer: map[string]string{"docker ps": "abc"}}
	c := NewScanCache(inner)

	for range 5 {
		out, err := c.Run(context.Background(), "docker", "ps")
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != "abc" {
			t.Fatalf("got %q, want %q", out, "abc")
		}
	}
	if n := inner.runs.Load(); n != 1 {
		t.Errorf("command ran %d times, want 1", n)
	}
}

// Different arguments are different questions and must not share an answer.
func TestScanCacheKeysOnArguments(t *testing.T) {
	inner := &countingRunner{perAnswer: map[string]string{
		"docker ps":       "running",
		"docker ps --all": "everything",
	}}
	c := NewScanCache(inner)

	first, _ := c.Run(context.Background(), "docker", "ps")
	second, _ := c.Run(context.Background(), "docker", "ps", "--all")
	if string(first) == string(second) {
		t.Fatalf("distinct commands shared a cache entry: both %q", first)
	}
	if n := inner.runs.Load(); n != 2 {
		t.Errorf("ran %d commands, want 2", n)
	}
}

// The single-flight behaviour is the point rather than a refinement: the
// compose and CVE checkers start together and ask for `docker compose ls` at
// the same moment, so a cache that only remembered completed calls would let
// both miss and both run — the exact duplication this exists to remove.
func TestScanCacheCollapsesConcurrentDuplicates(t *testing.T) {
	inner := &countingRunner{
		release:   make(chan struct{}),
		entered:   make(chan struct{}),
		perAnswer: map[string]string{"docker compose ls": "[]"},
	}
	c := NewScanCache(inner)

	const callers = 8
	var wg sync.WaitGroup
	results := make([][]byte, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := c.Run(context.Background(), "docker", "compose", "ls")
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
			}
			results[i] = out
		}()
	}

	// Hold the first caller inside the host call so the rest pile onto the
	// same in-flight key rather than finding a completed entry.
	<-inner.entered
	close(inner.release)
	wg.Wait()

	if n := inner.runs.Load(); n != 1 {
		t.Errorf("%d concurrent callers produced %d executions, want 1", callers, n)
	}
	for i, got := range results {
		if string(got) != "[]" {
			t.Errorf("caller %d got %q, want the shared result", i, got)
		}
	}
}

// A failure is an answer too. Re-running a command that just failed would
// make a checker's availability gate disagree with itself inside one scan.
func TestScanCacheRemembersFailures(t *testing.T) {
	want := errors.New("cannot connect to the Docker daemon")
	inner := &countingRunner{failWith: want}
	c := NewScanCache(inner)

	for range 3 {
		if _, err := c.Run(context.Background(), "docker", "ps"); !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	}
	if n := inner.runs.Load(); n != 1 {
		t.Errorf("failed command ran %d times, want 1", n)
	}
}

func TestScanCacheCachesLookPath(t *testing.T) {
	inner := &countingRunner{}
	c := NewScanCache(inner)

	for range 4 {
		path, err := c.LookPath("trivy")
		if err != nil || path != "/usr/bin/trivy" {
			t.Fatalf("LookPath = (%q, %v)", path, err)
		}
	}
	if n := inner.lookups.Load(); n != 1 {
		t.Errorf("LookPath resolved %d times, want 1", n)
	}
}

// A command and a LookPath for the same name are different questions.
func TestScanCacheSeparatesRunFromLookPath(t *testing.T) {
	inner := &countingRunner{perAnswer: map[string]string{"docker ": ""}}
	c := NewScanCache(inner)

	if _, err := c.Run(context.Background(), "docker"); err != nil {
		t.Fatal(err)
	}
	path, err := c.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/usr/bin/docker" {
		t.Errorf("LookPath returned %q — it read the Run cache", path)
	}
}
