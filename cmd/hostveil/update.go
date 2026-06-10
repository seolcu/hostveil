package main

import (
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

	url := fmt.Sprintf("https://github.com/seolcu/hostveil/releases/download/v%s/hostveil-%s-%s.tar.gz",
		version, runtime.GOOS, runtime.GOARCH)

	fmt.Printf("  Downloading hostveil %s...\n", version)
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "hostveil-update-*.tar.gz")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile) //nolint:errcheck

	if _, err := io.Copy(f, resp.Body); err != nil {
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
	if err := exec.Command("install", "-m", "755", tmpDir+"/hostveil", "/usr/bin/hostveil").Run(); err != nil {
		return fmt.Errorf("install failed: %w", err)
	}
	fmt.Println("  Updated to v" + version)
	return nil
}
