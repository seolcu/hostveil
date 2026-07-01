package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/tui"
)

func runUpdateCheckBackground(live *domain.ScanProgress) {
	live.SetToolStatus("update", domain.ToolRunning, "Checking for updates...")

	version, err := checkLatestVersion()
	if err != nil {
		live.SetToolStatus("update", domain.ToolDone, "Check failed")
		return
	}

	if version == "" || version == strings.TrimPrefix(tui.Version, "v") {
		live.SetToolStatus("update", domain.ToolDone, "Up to date")
	} else {
		live.SetUpdateAvailable(version)
		live.SetToolStatus("update", domain.ToolDone, fmt.Sprintf("v%s available (run 'hostveil update')", version))
	}

	if live.AllToolsDone() {
		live.Finalize()
	}
}

func checkLatestVersion() (string, error) {
	resp, err := httpClient.Get(checkLatestURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == 429 {
			return "", fmt.Errorf("GitHub API rate limited (status %d). Use --no-update or set --version", resp.StatusCode)
		}
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

func runUpdate() error {
	fmt.Print("  hostveil update: checking latest version...")

	version, err := checkLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}
	fmt.Printf(" %s\n", version)

	if version == strings.TrimPrefix(tui.Version, "v") {
		fmt.Println("  Already up to date.")
		return nil
	}

	archiveName := fmt.Sprintf("hostveil-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	url := fmt.Sprintf("%s/v%s/%s", releaseDownloadBaseURL, version, archiveName)

	fmt.Printf("  Downloading hostveil %s...\n", version)
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	archiveBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read download: %w", err)
	}

	fmt.Println("  Verifying checksum...")
	if err := verifyReleaseChecksum(version, archiveName, archiveBytes); err != nil {
		return err
	}

	f, err := os.CreateTemp("", "hostveil-update-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile) //nolint:errcheck

	if _, err := f.Write(archiveBytes); err != nil {
		_ = f.Close()
		return fmt.Errorf("write download: %w", err)
	}
	_ = f.Close()

	tmpDir, err := os.MkdirTemp("", "hostveil-extract-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	if err := exec.Command("tar", "xzf", tmpFile, "-C", tmpDir).Run(); err != nil {
		return fmt.Errorf("archive extraction failed: %w", err)
	}
	if err := exec.Command("install", "-m", "755", tmpDir+"/hostveil", hostveilInstallPath).Run(); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}
	fmt.Println("  ✓ Updated to v" + version)
	return nil
}

// verifyReleaseChecksum fetches the release's hostveil-checksums.txt and
// confirms archiveBytes' SHA-256 matches the entry for archiveName.
// Unlike the installer's best-effort checksum check (which fails open if
// the checksum file is unreachable, since it predates that file existing
// on every release), this fails closed: every hostveil release since
// v2.0.0 has published hostveil-checksums.txt, and this replaces a
// root-owned system binary, so an unreachable or non-matching checksum
// must abort the update rather than silently install unverified bytes.
func verifyReleaseChecksum(version, archiveName string, archiveBytes []byte) error {
	checksumsURL := fmt.Sprintf("%s/v%s/hostveil-checksums.txt", releaseDownloadBaseURL, version)
	resp, err := httpClient.Get(checksumsURL)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch checksums: HTTP %d", resp.StatusCode)
	}

	checksumBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}

	var expected string
	for _, line := range strings.Split(string(checksumBytes), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == archiveName {
			expected = fields[0]
			break
		}
	}
	if expected == "" {
		return fmt.Errorf("no checksum entry found for %s", archiveName)
	}

	sum := sha256.Sum256(archiveBytes)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s:\n  expected: %s\n  actual:   %s\nAborting for safety.", archiveName, expected, actual)
	}
	fmt.Println("  ✓ Checksum verified")
	return nil
}
