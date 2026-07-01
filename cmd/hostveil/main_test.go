package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/scan"
	"github.com/seolcu/hostveil/internal/tui"
)

func TestHasFlag(t *testing.T) {
	tests := []struct {
		args []string
		name string
		want bool
	}{
		{[]string{"cmd"}, "--foo", false},
		{[]string{"cmd", "--foo"}, "--foo", true},
		{[]string{"cmd", "--bar", "--foo"}, "--foo", true},
		{[]string{"cmd", "--foo", "value"}, "--foo", true},
		{[]string{"cmd"}, "--no-update", false},
		{[]string{"cmd", "--no-update"}, "--no-update", true},
	}
	for _, tt := range tests {
		got := hasFlag(tt.args, tt.name)
		if got != tt.want {
			t.Errorf("hasFlag(%v, %q) = %v, want %v", tt.args, tt.name, got, tt.want)
		}
	}
}

func TestScanningMessage(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"trivy", "Scanning container images..."},
		{"lynis", "Auditing system hardening..."},
		{"unknown", "Scanning..."},
		{"", "Scanning..."},
	}
	for _, tt := range tests {
		got := scan.ScanningMessage(tt.tool)
		if got != tt.want {
			t.Errorf("ScanningMessage(%q) = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

func TestHelpText(t *testing.T) {
	text := helpText()
	if !strings.Contains(text, "hostveil") {
		t.Error("helpText should contain 'hostveil'")
	}
	if !strings.Contains(text, "serve") {
		t.Error("helpText should contain 'serve'")
	}
	if !strings.Contains(text, "setup") {
		t.Error("helpText should contain 'setup'")
	}
}

func TestCheckLatestVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": "v1.2.3"}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "1.2.3" {
		t.Errorf("checkLatestVersion() = %q, want %q", version, "1.2.3")
	}
}

func TestCheckLatestVersion_EmptyTag(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": ""}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "" {
		t.Errorf("checkLatestVersion() = %q, want empty", version)
	}
}

func TestCheckLatestVersion_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for HTTP 500")
	}
}

func TestCheckLatestVersion_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for bad JSON")
	}
}

func TestCheckLatestVersion_NetworkError(t *testing.T) {
	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	_, err := checkLatestVersion()
	if err == nil {
		t.Error("checkLatestVersion() should return error for unreachable host")
	}
}

func TestCheckLatestVersion_ReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name": "v1.0.0"}`))
	}))
	defer ts.Close()

	oldURL := checkLatestURL
	oldClient := httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()

	checkLatestURL = ts.URL
	httpClient = ts.Client()

	version, err := checkLatestVersion()
	if err != nil {
		t.Fatalf("checkLatestVersion() returned error: %v", err)
	}
	if version != "1.0.0" {
		t.Errorf("checkLatestVersion() = %q, want %q", version, "1.0.0")
	}
}

// fakeInstallerScript is the fixed script body used by the setup tests
// below. Its sha256 is hardcoded in the tests that need a matching
// checksum server; if you change this, recompute it.
const fakeInstallerScript = "#!/bin/sh\necho hello\n"

// TestRunSetup_Success is hermetic: it points both installerURL and
// installerChecksumURL at local httptest servers so it never depends on
// GitHub being reachable or on scripts/install.sh.sha256's real content.
// Regression test: prior to this, installerChecksumURL was never
// overridden in any test, so runSetup() made a live network call to
// GitHub on every `go test` run, silently passing only because that URL
// 404s (verifyInstallerChecksum treats a fetch failure as "skip, don't
// fail" -- see TestVerifyInstallerChecksum_FetchFailureSkipsVerification).
func TestRunSetup_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeInstallerScript))
	}))
	defer ts.Close()

	sum := sha256.Sum256([]byte(fakeInstallerScript))
	checksumTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s  install.sh\n", hex.EncodeToString(sum[:]))
	}))
	defer checksumTS.Close()

	oldURL := installerURL
	oldChecksumURL := installerChecksumURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		installerChecksumURL = oldChecksumURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	installerChecksumURL = checksumTS.URL
	httpClient = ts.Client()

	err := runSetup()
	if err != nil {
		t.Fatalf("runSetup() returned error: %v", err)
	}
}

// TestRunSetup_ChecksumMismatchFailsClosed is a regression test: if
// installer checksum verification is ever reachable but the checksum
// does not match, runSetup must fail rather than silently execute an
// unverified script.
func TestRunSetup_ChecksumMismatchFailsClosed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fakeInstallerScript))
	}))
	defer ts.Close()

	checksumTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s  install.sh\n", strings.Repeat("0", 64))
	}))
	defer checksumTS.Close()

	oldURL := installerURL
	oldChecksumURL := installerChecksumURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		installerChecksumURL = oldChecksumURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	installerChecksumURL = checksumTS.URL
	httpClient = ts.Client()

	err := runSetup()
	if err == nil {
		t.Fatal("runSetup() should fail on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}
}

// TestVerifyInstallerChecksum_FetchFailureSkipsVerification documents the
// intentional fail-open behavior when the checksum file itself cannot be
// fetched (e.g. network error, or -- as was the case in production until
// scripts/install.sh.sha256 was published -- a 404). This is deliberate:
// setup.go treats the checksum as advisory defense-in-depth, not a hard
// requirement, so a missing checksum degrades to "unverified" rather than
// blocking `hostveil setup` outright.
func TestVerifyInstallerChecksum_FetchFailureSkipsVerification(t *testing.T) {
	oldChecksumURL := installerChecksumURL
	oldClient := httpClient
	defer func() {
		installerChecksumURL = oldChecksumURL
		httpClient = oldClient
	}()

	installerChecksumURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	if err := verifyInstallerChecksum([]byte(fakeInstallerScript)); err != nil {
		t.Errorf("expected nil error on checksum fetch failure, got: %v", err)
	}
}

func TestRunSetup_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	httpClient = ts.Client()

	err := runSetup()
	if err == nil {
		t.Fatal("runSetup() should return error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("runSetup() error should mention status code, got: %v", err)
	}
}

func TestRunSetup_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = ts.URL
	httpClient = ts.Client()

	err := runSetup()
	if err == nil {
		t.Fatal("runSetup() should return error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("runSetup() error should mention status code, got: %v", err)
	}
}

func TestRunSetup_NetworkError(t *testing.T) {
	oldURL := installerURL
	oldClient := httpClient
	defer func() {
		installerURL = oldURL
		httpClient = oldClient
	}()

	installerURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	err := runSetup()
	if err == nil {
		t.Error("runSetup() should return error for unreachable host")
	}
}

// buildTarGz builds a valid gzipped tar archive containing a single file
// "hostveil" with the given content, matching the layout GoReleaser
// produces (the binary at the archive root).
func buildTarGz(t *testing.T, content []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "out.tar.gz")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("create temp archive: %v", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "hostveil", Mode: 0755, Size: int64(len(content))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close archive file: %v", err)
	}
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatalf("read back archive: %v", err)
	}
	return data
}

// setupUpdateTestServer starts one httptest.Server handling the two
// endpoints runUpdate needs beyond the version-check API: the archive
// download and the checksums file. archiveHandler and checksumsHandler
// let each test customize just the response it cares about; nil means
// "200 with the real matching content".
func setupUpdateTestServer(t *testing.T, version string, archive []byte, archiveHandler, checksumsHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(archive)
	archiveName := fmt.Sprintf("hostveil-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)

	mux := http.NewServeMux()
	if archiveHandler != nil {
		mux.HandleFunc("/v"+version+"/"+archiveName, archiveHandler)
	} else {
		mux.HandleFunc("/v"+version+"/"+archiveName, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(archive)
		})
	}
	if checksumsHandler != nil {
		mux.HandleFunc("/v"+version+"/hostveil-checksums.txt", checksumsHandler)
	} else {
		mux.HandleFunc("/v"+version+"/hostveil-checksums.txt", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), archiveName)
		})
	}
	return httptest.NewServer(mux)
}

// TestRunUpdate_Success is a regression test for a missing security
// control: runUpdate previously downloaded and installed the release
// archive with zero checksum verification, despite SECURITY.md claiming
// "hostveil update ... re-verifies checksums before installing." This
// drives the full success path, including a real install(1) invocation,
// redirected at a t.TempDir() path via hostveilInstallPath so it never
// touches the real system.
func TestRunUpdate_Success(t *testing.T) {
	binContent := []byte("fake hostveil binary content")
	archive := buildTarGz(t, binContent)
	ts := setupUpdateTestServer(t, "9.9.9", archive, nil, nil)
	defer ts.Close()

	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v9.9.9"}`)
	}))
	defer latestTS.Close()

	installDir := t.TempDir()
	installPath := filepath.Join(installDir, "hostveil")

	oldCheckURL, oldBaseURL, oldInstallPath, oldClient := checkLatestURL, releaseDownloadBaseURL, hostveilInstallPath, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		hostveilInstallPath = oldInstallPath
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	releaseDownloadBaseURL = ts.URL
	hostveilInstallPath = installPath
	httpClient = ts.Client()

	if err := runUpdate(); err != nil {
		t.Fatalf("runUpdate() returned error: %v", err)
	}

	got, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatalf("expected binary installed at %s: %v", installPath, err)
	}
	if string(got) != string(binContent) {
		t.Errorf("installed binary content = %q, want %q", got, binContent)
	}
	info, err := os.Stat(installPath)
	if err != nil {
		t.Fatalf("stat installed binary: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Errorf("installed binary mode = %o, want 0755", info.Mode().Perm())
	}
}

// TestRunUpdate_AlreadyUpToDate confirms the early-return path never
// touches the network for the archive or checksum.
func TestRunUpdate_AlreadyUpToDate(t *testing.T) {
	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "`+tui.Version+`"}`)
	}))
	defer latestTS.Close()

	oldCheckURL, oldBaseURL, oldClient := checkLatestURL, releaseDownloadBaseURL, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	// Point releaseDownloadBaseURL at an address that would fail any
	// request, to prove the archive/checksum path is never reached.
	releaseDownloadBaseURL = "http://127.0.0.1:1"
	httpClient = latestTS.Client()

	if err := runUpdate(); err != nil {
		t.Fatalf("runUpdate() returned error: %v", err)
	}
}

// TestRunUpdate_ChecksumMismatchFailsClosed is the core regression test:
// a tampered or corrupted archive must abort the update, not install.
func TestRunUpdate_ChecksumMismatchFailsClosed(t *testing.T) {
	archive := buildTarGz(t, []byte("fake hostveil binary content"))
	badChecksums := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s  hostveil-%s-%s.tar.gz\n", strings.Repeat("0", 64), runtime.GOOS, runtime.GOARCH)
	}
	ts := setupUpdateTestServer(t, "9.9.9", archive, nil, badChecksums)
	defer ts.Close()

	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v9.9.9"}`)
	}))
	defer latestTS.Close()

	installPath := filepath.Join(t.TempDir(), "hostveil")
	oldCheckURL, oldBaseURL, oldInstallPath, oldClient := checkLatestURL, releaseDownloadBaseURL, hostveilInstallPath, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		hostveilInstallPath = oldInstallPath
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	releaseDownloadBaseURL = ts.URL
	hostveilInstallPath = installPath
	httpClient = ts.Client()

	err := runUpdate()
	if err == nil {
		t.Fatal("runUpdate() should fail on checksum mismatch")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %v", err)
	}
	if _, statErr := os.Stat(installPath); !os.IsNotExist(statErr) {
		t.Error("binary must NOT be installed when checksum verification fails")
	}
}

// TestRunUpdate_ChecksumEntryMissing covers a checksums file that is
// reachable but has no entry for this OS/ARCH's archive name.
func TestRunUpdate_ChecksumEntryMissing(t *testing.T) {
	archive := buildTarGz(t, []byte("fake hostveil binary content"))
	emptyChecksums := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "deadbeef  hostveil-someother-arch.tar.gz\n")
	}
	ts := setupUpdateTestServer(t, "9.9.9", archive, nil, emptyChecksums)
	defer ts.Close()

	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v9.9.9"}`)
	}))
	defer latestTS.Close()

	installPath := filepath.Join(t.TempDir(), "hostveil")
	oldCheckURL, oldBaseURL, oldInstallPath, oldClient := checkLatestURL, releaseDownloadBaseURL, hostveilInstallPath, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		hostveilInstallPath = oldInstallPath
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	releaseDownloadBaseURL = ts.URL
	hostveilInstallPath = installPath
	httpClient = ts.Client()

	err := runUpdate()
	if err == nil {
		t.Fatal("runUpdate() should fail when no checksum entry matches")
	}
	if !strings.Contains(err.Error(), "no checksum entry found") {
		t.Errorf("expected 'no checksum entry found' error, got: %v", err)
	}
}

// TestRunUpdate_ChecksumFetchFailsClosed covers the checksums file being
// completely unreachable (e.g. HTTP 404, matching the state install.sh's
// checksum was in before it was published). Unlike the installer's
// fail-open checksum check, this must fail closed.
func TestRunUpdate_ChecksumFetchFailsClosed(t *testing.T) {
	archive := buildTarGz(t, []byte("fake hostveil binary content"))
	notFound := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	ts := setupUpdateTestServer(t, "9.9.9", archive, nil, notFound)
	defer ts.Close()

	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v9.9.9"}`)
	}))
	defer latestTS.Close()

	installPath := filepath.Join(t.TempDir(), "hostveil")
	oldCheckURL, oldBaseURL, oldInstallPath, oldClient := checkLatestURL, releaseDownloadBaseURL, hostveilInstallPath, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		hostveilInstallPath = oldInstallPath
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	releaseDownloadBaseURL = ts.URL
	hostveilInstallPath = installPath
	httpClient = ts.Client()

	err := runUpdate()
	if err == nil {
		t.Fatal("runUpdate() should fail closed when checksums file is unreachable")
	}
	if _, statErr := os.Stat(installPath); !os.IsNotExist(statErr) {
		t.Error("binary must NOT be installed when checksum file is unreachable")
	}
}

// TestRunUpdate_ArchiveDownloadHTTPError covers the archive download
// itself failing.
func TestRunUpdate_ArchiveDownloadHTTPError(t *testing.T) {
	archive := buildTarGz(t, []byte("unused"))
	notFound := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	ts := setupUpdateTestServer(t, "9.9.9", archive, notFound, nil)
	defer ts.Close()

	latestTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"tag_name": "v9.9.9"}`)
	}))
	defer latestTS.Close()

	oldCheckURL, oldBaseURL, oldClient := checkLatestURL, releaseDownloadBaseURL, httpClient
	defer func() {
		checkLatestURL = oldCheckURL
		releaseDownloadBaseURL = oldBaseURL
		httpClient = oldClient
	}()
	checkLatestURL = latestTS.URL
	releaseDownloadBaseURL = ts.URL
	httpClient = ts.Client()

	err := runUpdate()
	if err == nil {
		t.Fatal("runUpdate() should fail when archive download 404s")
	}
	if !strings.Contains(err.Error(), "download failed") {
		t.Errorf("expected download failed error, got: %v", err)
	}
}

// TestRunUpdate_VersionCheckError covers checkLatestVersion itself failing.
func TestRunUpdate_VersionCheckError(t *testing.T) {
	oldURL, oldClient := checkLatestURL, httpClient
	defer func() {
		checkLatestURL = oldURL
		httpClient = oldClient
	}()
	checkLatestURL = "http://127.0.0.1:1/"
	httpClient = &http.Client{}

	err := runUpdate()
	if err == nil {
		t.Fatal("runUpdate() should fail when version check fails")
	}
	if !strings.Contains(err.Error(), "failed to check for updates") {
		t.Errorf("expected version check error, got: %v", err)
	}
}
