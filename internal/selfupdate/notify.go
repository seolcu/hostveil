package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/platform"
)

// CheckInterval is how often hostveil looks for a newer release.
//
// A day, because the thing being watched moves on the order of weeks and the
// question a scan is answering has nothing to do with it. A check on every run
// would put a request to GitHub behind every cron entry on every host that
// installed this, which is a cost paid by somebody else's infrastructure for
// information that has not changed.
const CheckInterval = 24 * time.Hour

// checkTimeout bounds the request. The check is decoration on a scan, so it
// gets a short leash: if GitHub is slow, the scan finishes without the notice
// and the next run picks it up.
const checkTimeout = 5 * time.Second

// cacheName is the file inside the state directory.
const cacheName = "update-check.json"

// Cache is what the last check found. It is written even when the check found
// nothing new, because the timestamp is the half that decides whether to ask
// again.
type Cache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
}

// LoadCache reads the last result. A missing or unreadable file is an empty
// cache and not an error: this is a convenience, and a scan must never fail
// because of it.
func LoadCache(dir string) Cache {
	data, err := os.ReadFile(filepath.Join(dir, cacheName)) //nolint:gosec // a path hostveil owns
	if err != nil {
		return Cache{}
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return Cache{}
	}
	return c
}

// SaveCache records a result, best effort.
func SaveCache(dir string, c Cache) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	// The same modes the rest of the state directory uses. This file is not
	// sensitive, but it shares a directory with the saved scans and the
	// checkpoints, and one entry with looser modes than its neighbours is a
	// question somebody has to answer later.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = platform.WriteFileAtomic(filepath.Join(dir, cacheName), data, 0o600)
}

// Due reports whether the cache is old enough to ask again.
func (c Cache) Due(now time.Time) bool {
	return now.Sub(c.CheckedAt) >= CheckInterval
}

// Notice is the one line an interface shows, or "" when there is nothing to
// say.
//
// Nothing to say covers three cases that are worth keeping apart from each
// other only in the code: no check has run, the check found the version this
// binary already is, or the binary is a development build whose version is not
// a release at all and would compare unequal to everything forever.
func (c Cache) Notice(current string) string {
	if c.Latest == "" || SameVersion(current, c.Latest) || !looksLikeRelease(current) {
		return ""
	}
	return fmt.Sprintf("hostveil %s is available (this is %s). Run `hostveil update`.", c.Latest, current)
}

// looksLikeRelease keeps anything that is not a published version quiet.
//
// The default stamp is `v3-dev`, and telling its user that 3.17.0 is available
// on every scan is noise about a state they chose. A distribution's own
// `3.17.0-1` is rejected by the same rule and for a better reason: that binary
// belongs to a packager, and its version is not one this project ever
// published to compare against.
//
// The shape is checked rather than just the dash, because anything unequal to
// the latest release reads as out of date, and a version string this program
// cannot recognise should not be the basis for telling somebody to run an
// update.
func looksLikeRelease(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "" || !strings.Contains(v, ".") {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// CheckInBackground refreshes the cache without making anything wait for it.
//
// It returns immediately. Whatever it learns is read by the *next* thing that
// asks, which is usually the end of the same scan and sometimes the next run.
// That is the whole design: a scan's timing is a property of the host being
// scanned, and an update check has no business appearing in it.
//
// Nothing is reported when it fails. A host behind a proxy, or one with no
// route to GitHub at all, is not a host with a problem hostveil should be
// telling it about.
func CheckInBackground(ctx context.Context, c Client, dir string, now time.Time) {
	if LoadCache(dir).Due(now) {
		go func() {
			// This is a best-effort background nicety — scan, tui and serve
			// all fire it and move on without waiting — and every other way
			// it can fail (network down, GitHub unreachable, a bad redirect)
			// already just returns quietly. A panic must degrade the same
			// way: nothing here is worth ending the command that triggered
			// it, on a goroutine whose caller has no way to know it existed.
			defer func() { _ = recover() }()
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), checkTimeout)
			defer cancel()
			rel, err := Latest(ctx, c)
			if err != nil {
				return
			}
			SaveCache(dir, Cache{CheckedAt: now, Latest: rel.Version})
		}()
	}
}
