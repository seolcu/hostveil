package selfupdate

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The interval is the whole reason the cache exists. A check that ran on every
// scan would put a request to GitHub behind every cron entry on every host,
// which is a cost paid by somebody else for an answer that has not changed.
func TestTheCacheDecidesWhenToAskAgain(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		checked time.Time
		want    bool
	}{
		{"never checked", time.Time{}, true},
		{"checked a minute ago", now.Add(-time.Minute), false},
		{"checked just under the interval", now.Add(-CheckInterval + time.Second), false},
		{"checked exactly the interval ago", now.Add(-CheckInterval), true},
		{"checked a week ago", now.Add(-7 * 24 * time.Hour), true},
		// A host whose clock moved backwards, or a cache copied from
		// elsewhere. Asking again is the harmless direction to be wrong in.
		{"checked in the future", now.Add(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := (Cache{CheckedAt: tc.checked}).Due(now); got != tc.want {
				t.Errorf("Due = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheCacheSurvivesTheTripThroughDisk(t *testing.T) {
	dir := t.TempDir()
	if got := LoadCache(dir); got.Latest != "" || !got.CheckedAt.IsZero() {
		t.Fatalf("an empty directory produced %+v, want a zero cache", got)
	}

	when := time.Date(2026, 8, 13, 9, 30, 0, 0, time.UTC)
	SaveCache(dir, Cache{CheckedAt: when, Latest: "3.18.0"})
	got := LoadCache(dir)
	if got.Latest != "3.18.0" || !got.CheckedAt.Equal(when) {
		t.Errorf("read back %+v, want 3.18.0 at %v", got, when)
	}

	// Damage is not an error either. This is a convenience on the side of a
	// scan, and a scan must never fail because of it.
	if err := os.WriteFile(filepath.Join(dir, cacheName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCache(dir); got.Latest != "" {
		t.Errorf("a corrupt cache produced %+v, want a zero cache", got)
	}
}

// The three silences matter more than the one sentence. A notice printed under
// every scan on a host that is already current, or on a development build that
// will never compare equal to anything, is noise the operator cannot turn off
// by doing what it says.
func TestTheNoticeStaysQuietUnlessThereIsSomethingToSay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cache   Cache
		current string
		want    bool
	}{
		{"nothing checked yet", Cache{}, "v3.17.0", false},
		{"already current", Cache{Latest: "3.17.0"}, "v3.17.0", false},
		{"the default development stamp", Cache{Latest: "3.17.0"}, "v3-dev", false},
		{"a distribution's own build", Cache{Latest: "3.17.0"}, "3.17.0-1ubuntu1", false},
		{"a version string nobody recognises", Cache{Latest: "3.17.0"}, "v", false},
		{"a version with no leading v", Cache{Latest: "3.18.0"}, "3.17.0", true},
		{"no version stamped at all", Cache{Latest: "3.17.0"}, "", false},
		{"a newer release", Cache{Latest: "3.18.0"}, "v3.17.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := tc.cache.Notice(tc.current)
			if (note != "") != tc.want {
				t.Fatalf("Notice = %q, want something=%v", note, tc.want)
			}
			if tc.want && !contains(note, "hostveil update") {
				t.Errorf("the notice does not say what to do about it: %q", note)
			}
		})
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// slowClient blocks until released, so the test can prove the caller was not
// waiting on it.
type slowClient struct{ release chan struct{} }

func (c slowClient) Do(*http.Request) (*http.Response, error) {
	<-c.release
	return nil, os.ErrDeadlineExceeded
}

// A scan's timing is a property of the host being scanned. An update check has
// no business appearing in it, so the call returns before the request does.
func TestTheBackgroundCheckDoesNotHoldUpTheCaller(t *testing.T) {
	c := slowClient{release: make(chan struct{})}
	defer close(c.release)

	done := make(chan struct{})
	go func() {
		CheckInBackground(context.Background(), c, t.TempDir(), time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("CheckInBackground blocked on the request it was supposed to leave running")
	}
}

// The cache is what stops the request, so a fresh one must stop it before the
// client is ever touched.
func TestAFreshCacheMakesNoRequestAtAll(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	SaveCache(dir, Cache{CheckedAt: now, Latest: "3.17.0"})

	asked := make(chan struct{}, 1)
	CheckInBackground(context.Background(), countingClient{asked}, dir, now)
	select {
	case <-asked:
		t.Fatal("a cache written seconds ago still produced a request to GitHub")
	case <-time.After(200 * time.Millisecond):
	}
}

type countingClient struct{ asked chan struct{} }

func (c countingClient) Do(*http.Request) (*http.Response, error) {
	c.asked <- struct{}{}
	return nil, os.ErrDeadlineExceeded
}

// The check outlives the context the scan was cancelled with, but only up to
// its own timeout: it is detached so a fast scan does not abort it mid-flight,
// and bounded so it cannot outlive the process usefully.
func TestTheCheckOutlivesTheScanContextItWasStartedFrom(t *testing.T) {
	dir := t.TempDir()
	c := stubClient{head: "https://github.com/seolcu/hostveil/releases/tag/v3.18.0"}
	// A cancelled context, to prove the goroutine does not inherit it.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	CheckInBackground(ctx, ctxRespecting{c}, dir, time.Now())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if LoadCache(dir).Latest == "3.18.0" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the check did not record its result; a cancelled scan context stopped it")
}

// ctxRespecting refuses a request whose context is already done, which is what
// net/http does and what a stub that ignores the context does not. Without it
// the test above passes with the detachment removed.
type ctxRespecting struct{ inner Client }

func (c ctxRespecting) Do(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return c.inner.Do(req)
}
