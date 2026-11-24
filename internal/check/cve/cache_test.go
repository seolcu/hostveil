package cve

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/platform"
	"github.com/seolcu/hostveil/internal/resultcache"
)

const dbV1 = `{"Version":"0.76.2","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-11-24T13:06:50Z"}}`
const dbV2 = `{"Version":"0.76.2","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-11-25T13:06:50Z"}}`

// cachedProject is composeProject with the two inputs the cache keys on.
func cachedProject(t *testing.T) *scriptRunner {
	t.Helper()
	// The test machine's own package database would otherwise key a host
	// entry; these tests are about images.
	saved := hostPackageDBs
	hostPackageDBs = nil
	t.Cleanup(func() { hostPackageDBs = saved })
	r := composeProject(t)
	r.trivy["redis:7"] = oneVuln
	r.trivy["postgres:13"] = oneVuln
	r.dbJSON = dbV1
	r.imageIDs = map[string]string{"redis:7": "sha256:aaa", "postgres:13": "sha256:bbb"}
	return r
}

func imageScans(r *scriptRunner) []string {
	var out []string
	for _, c := range r.trivyCalls() {
		if c != "warm" && c != "json" {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

func checkCached(t *testing.T, dir string, r *scriptRunner) int {
	t.Helper()
	fs, err := NewCached(resultcache.New(dir, 64, 64<<20)).Check(context.Background(), platform.Env{Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	return len(fs)
}

// An unchanged image against an unchanged database gives the same report, so
// the second scan reads it back and starts no Trivy process for it.
func TestCacheReusesTheReportOfAnUnchangedImage(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	first := checkCached(t, dir, r)
	if got := imageScans(r); len(got) != 2 {
		t.Fatalf("the first scan analyses both images, got %v", got)
	}
	second := checkCached(t, dir, r)
	if got := imageScans(r); len(got) != 2 {
		t.Fatalf("the second scan must not run Trivy on either image again, got %v", got)
	}
	if first != second || first == 0 {
		t.Fatalf("a cached report must produce the same findings: %d then %d", first, second)
	}
}

// A refreshed database can report new vulnerabilities in an old image, so it
// invalidates every entry.
func TestCacheMissesWhenTheDatabaseChanges(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	checkCached(t, dir, r)
	r.dbJSON = dbV2
	checkCached(t, dir, r)
	if got := imageScans(r); len(got) != 4 {
		t.Fatalf("a new database must rescan both images, got %v", got)
	}
}

// A re-pulled tag is a different image.
func TestCacheMissesWhenTheImageChanges(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	checkCached(t, dir, r)
	r.imageIDs["redis:7"] = "sha256:ccc"
	checkCached(t, dir, r)
	if got := imageScans(r); !slices.Equal(got, []string{"postgres:13", "redis:7", "redis:7"}) {
		t.Fatalf("only the changed image is rescanned, got %v", got)
	}
}

// Without a database identity nothing can say whether a report is current,
// so nothing is stored or read.
func TestCacheIsOffWithoutADatabaseIdentity(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	r.dbJSON = ""
	checkCached(t, dir, r)
	checkCached(t, dir, r)
	if got := imageScans(r); len(got) != 4 {
		t.Fatalf("every scan must run Trivy, got %v", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("nothing may be stored, found %d entries", len(entries))
	}
}

// An image docker does not hold would be fetched from a registry, where the
// tag can move, so its report is not stored.
func TestCacheSkipsAnImageDockerDoesNotHold(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	delete(r.imageIDs, "postgres:13")
	checkCached(t, dir, r)
	checkCached(t, dir, r)
	if got := imageScans(r); !slices.Equal(got, []string{"postgres:13", "postgres:13", "redis:7"}) {
		t.Fatalf("only the image with an ID is cached, got %v", got)
	}
}

// A failed scan is never stored, so it is never replayed as a result.
func TestCacheDoesNotStoreAFailedScan(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	r.trivyErr["redis:7"] = true
	if _, err := NewCached(resultcache.New(dir, 64, 64<<20)).Check(context.Background(), platform.Env{Runner: r}); err == nil {
		t.Fatal("one image failing must degrade the axis")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("only the image that scanned may be stored, found %d entries", len(entries))
	}
}

// A truncated or edited entry is a miss, and the scan replaces it.
func TestCacheTreatsACorruptEntryAsAMiss(t *testing.T) {
	dir := t.TempDir()
	r := cachedProject(t)
	checkCached(t, dir, r)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if err := os.WriteFile(filepath.Join(dir, e.Name()), []byte(`{"Results":[`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if n := checkCached(t, dir, r); n == 0 {
		t.Fatal("a corrupt entry must not hide the image's findings")
	}
	if got := imageScans(r); len(got) != 4 {
		t.Fatalf("both corrupt entries must be rescanned, got %v", got)
	}
}

// The host is keyed by its package database, so an upgrade invalidates it.
func TestCacheKeysTheHostOnItsPackageDatabase(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(status, []byte("Package: openssl\nVersion: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := hostPackageDBs
	hostPackageDBs = []string{status}
	t.Cleanup(func() { hostPackageDBs = saved })

	r := &scriptRunner{noDocker: true, host: hostUnpatched, dbJSON: dbV1}
	hostScans := func() int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.hostCalls
	}
	checkCached(t, dir, r)
	checkCached(t, dir, r)
	if n := hostScans(); n != 1 {
		t.Fatalf("an unchanged host is scanned once, got %d", n)
	}
	if err := os.WriteFile(status, []byte("Package: openssl\nVersion: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkCached(t, dir, r)
	if n := hostScans(); n != 2 {
		t.Fatalf("an upgraded package set must be rescanned, got %d", n)
	}
}
