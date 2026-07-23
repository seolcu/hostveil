package platform

import (
	"context"
	"strings"
	"sync"
)

// ScanCache is a CommandRunner that remembers each command's result for the
// life of one scan, and runs concurrent duplicates only once.
//
// Checkers are strictly read-only (see check.Checker) and all nine run at
// the same time, so several of them independently ask the host the same
// question. The compose and CVE checkers each ran `docker compose ls`,
// parsed every compose file, then ran `docker ps` and `docker inspect`
// across every container ID — twice per scan, concurrently, with the
// inspect output alone reaching megabytes on a busy host. The ports checker
// separately re-probed the firewall the firewall checker had just probed.
//
// Deduplicating at the runner rather than in the checkers is what keeps that
// from becoming an inventory object every checker has to be taught about:
// nothing in check/ changes, and a future checker gets the sharing for free.
//
// The single-flight behaviour is the point, not an optimization on top of
// the cache. The duplicate callers start together, so a plain
// cache-after-the-fact would let both miss and both run — exactly the case
// this exists to remove.
//
// # Scope
//
// A ScanCache must live no longer than one scan. It is the engine's job to
// build a fresh one per scan and hand it out through Env, and to keep using
// the uncached runner for fixes: caching an exec fix's command would be
// wrong twice over, since it mutates the host and its result is not a
// question with a stable answer.
type ScanCache struct {
	inner CommandRunner

	mu    sync.Mutex
	calls map[string]*cachedCall
}

// cachedCall is one command's result, or its in-flight execution. done is
// closed when out/err are final; readers wait on it rather than re-running.
type cachedCall struct {
	done chan struct{}
	out  []byte
	err  error
}

// NewScanCache wraps r so identical commands within one scan run once.
func NewScanCache(r CommandRunner) *ScanCache {
	return &ScanCache{inner: r, calls: map[string]*cachedCall{}}
}

// Run returns the command's cached stdout, running it only if this is the
// first request for it.
//
// The returned slice is shared with every other caller of the same command.
// That is safe for the way command output is used here — parsed, never
// written to — and copying a multi-megabyte `docker inspect` result per
// caller would give back the memory the sharing just saved.
func (c *ScanCache) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	key := name + "\x00" + strings.Join(args, "\x00")

	c.mu.Lock()
	if call, ok := c.calls[key]; ok {
		c.mu.Unlock()
		<-call.done // may already be closed
		return call.out, call.err
	}
	call := &cachedCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	call.out, call.err = c.inner.Run(ctx, name, args...)
	close(call.done)
	return call.out, call.err
}

// LookPath resolves a binary, caching the answer.
//
// Availability gates call this repeatedly for the same handful of names
// (docker, ss, trivy, ufw), and a binary does not appear or vanish partway
// through a scan.
func (c *ScanCache) LookPath(name string) (string, error) {
	key := "\x00lookpath\x00" + name

	c.mu.Lock()
	if call, ok := c.calls[key]; ok {
		c.mu.Unlock()
		<-call.done
		return string(call.out), call.err
	}
	call := &cachedCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	path, err := c.inner.LookPath(name)
	call.out, call.err = []byte(path), err
	close(call.done)
	return path, err
}
