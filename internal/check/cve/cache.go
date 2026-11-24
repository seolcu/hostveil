package cve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/seolcu/hostveil/internal/platform"
)

// resultCache keeps Trivy's JSON report for one scan target on disk, so the
// next scan of an unchanged target is a file read.
//
// Trivy is the slowest thing Hostveil runs. On the demo VM the CVE domain
// took 41 of a scan's 42 seconds, every time, because each run analysed the
// same seven images against the same database again.
//
// A report is a function of three inputs: the target's content, the
// vulnerability database, and the Trivy release that matched one against
// the other. The key hashes all three, plus the scan arguments and this
// file's format version:
//
//   - an image is named by its ID, the digest of its configuration, so a
//     re-pulled tag or a rebuilt image is a different key;
//   - the host is named by the digest of its package database files, so
//     installing or upgrading anything is a different key;
//   - the database is named by its UpdatedAt stamp, read after warmCache
//     has had the chance to refresh it.
//
// A hit is therefore the report Trivy would produce now. The database
// refresh still runs on every scan (45ms when there is nothing new), so a
// cached report never keeps an old database alive: a new one changes the
// key, and every target is analysed against it once.
//
// Only a report that parsed is stored, and only a target that scanned in
// full gets there, so a failure is never replayed. An unreadable or
// malformed entry is a miss.
type resultCache struct {
	store Store // nil disables the cache

	once sync.Once
	db   string // vulnerability database identity; "" disables the cache
	warm error  // warmCache's result, shared with scanAll
}

// Store is where reports are kept between scans. internal/resultcache
// implements it in Hostveil's state directory; the checker only reads and
// hands bytes over, which keeps it read-only.
type Store interface {
	Get(key string) ([]byte, bool)
	Put(key string, data []byte)
	Prune()
}

// cacheFormat is part of every key. Bump it when the stored bytes or the way
// a key is built changes, and old entries stop matching.
const cacheFormat = "2"

// prepare refreshes the database and records its identity. It runs once per
// scan, before the first target, because the identity has to describe the
// database the scans will use.
func (c *resultCache) prepare(ctx context.Context, r platform.CommandRunner) {
	c.once.Do(func() {
		c.warm = warmCache(ctx, r)
		if c.store != nil {
			c.db = dbIdentity(ctx, r)
		}
	})
}

// warmed reports whether the database download succeeded, running it if no
// one has yet.
func (c *resultCache) warmed(ctx context.Context, r platform.CommandRunner) bool {
	c.prepare(ctx, r)
	return c.warm == nil
}

func (c *resultCache) enabled() bool { return c != nil && c.store != nil && c.db != "" }

// key names one report.
func (c *resultCache) key(kind, subject string, args []string) string {
	h := sha256.New()
	for _, part := range append([]string{cacheFormat, kind, subject, c.db}, args...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// get returns a stored report. A malformed entry is a miss.
func (c *resultCache) get(key string) ([]byte, bool) {
	if !c.enabled() {
		return nil, false
	}
	data, ok := c.store.Get(key)
	if !ok || !json.Valid(data) {
		return nil, false
	}
	return data, true
}

// put stores a report, reduced to the fields this package reads (see
// compactReport).
func (c *resultCache) put(key string, data []byte) {
	if !c.enabled() {
		return
	}
	compact, err := compactReport(data)
	if err != nil {
		return
	}
	c.store.Put(key, compact)
}

func (c *resultCache) prune() {
	if c != nil && c.store != nil {
		c.store.Prune()
	}
}

// compactReport keeps the fields trivyReport declares and drops the rest.
// Trivy's own report carries every advisory's description and references:
// the Ubuntu 24.04 demo host's was 111MB, and reading it back cost more than
// the scan it replaced. The same report through trivyReport is 3MB.
func compactReport(data []byte) ([]byte, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return json.Marshal(r)
}

// dbIdentity names the vulnerability database Trivy will scan with, from
// `trivy version --format json`. It is "" when there is no database yet or
// the output cannot be read, which turns the cache off for this scan.
func dbIdentity(ctx context.Context, r platform.CommandRunner) string {
	out, err := r.Run(ctx, "trivy", "version", "--format", "json")
	if err != nil {
		return ""
	}
	var v struct {
		Version         string
		VulnerabilityDB *struct {
			Version   int
			UpdatedAt string
		}
		JavaDB *struct {
			UpdatedAt string
		}
	}
	if json.Unmarshal(out, &v) != nil || v.VulnerabilityDB == nil || v.VulnerabilityDB.UpdatedAt == "" {
		return ""
	}
	parts := []string{v.Version, strconv.Itoa(v.VulnerabilityDB.Version), v.VulnerabilityDB.UpdatedAt}
	if v.JavaDB != nil {
		parts = append(parts, v.JavaDB.UpdatedAt)
	}
	return strings.Join(parts, "|")
}

// imageID returns the local image's ID, or "" when docker does not have it
// (Trivy would then fetch it from a registry, and a tag there can move, so
// that scan is not cached).
func imageID(ctx context.Context, r platform.CommandRunner, image string) string {
	out, err := r.Run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(string(out))
	if !strings.HasPrefix(id, "sha256:") || strings.ContainsAny(id, " \n") {
		return ""
	}
	return id
}

// hostPackageDBs are the files a package manager rewrites whenever anything is
// installed, upgraded or removed, plus os-release for the distribution
// version Trivy matches against. Missing files are skipped.
var hostPackageDBs = []string{
	"/etc/os-release",
	"/var/lib/dpkg/status",
	"/var/lib/rpm/rpmdb.sqlite",
	"/var/lib/rpm/Packages",
	"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	"/lib/apk/db/installed",
}

// hostDigest hashes the package database files that exist. It is "" when
// none but os-release does, because then nothing names the installed set.
func hostDigest(paths []string) string {
	h := sha256.New()
	found := 0
	for _, p := range paths {
		f, err := os.Open(p) //nolint:gosec // G304: p is one of hostPackageDBs, a fixed list of system paths
		if err != nil {
			continue
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return ""
		}
		if !strings.HasSuffix(p, "os-release") {
			found++
		}
	}
	if found == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
