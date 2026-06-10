package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

func runSetup() error {
	fmt.Println("  hostveil setup — installing dependencies")
	fmt.Println()

	f, err := os.CreateTemp("", "hostveil-install-*.sh")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpFile := f.Name()
	defer os.Remove(tmpFile) //nolint:errcheck

	resp, err := httpClient.Get(installerURL)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to download installer: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		_ = f.Close()
		return fmt.Errorf("installer download failed: HTTP %d", resp.StatusCode)
	}

	scriptBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to read installer: %w", err)
	}
	if _, err := f.Write(scriptBytes); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write installer: %w", err)
	}
	_ = f.Close()

	if err := verifyInstallerChecksum(scriptBytes); err != nil {
		return err
	}

	if err := os.Chmod(tmpFile, 0755); err != nil {
		return fmt.Errorf("failed to make installer executable: %w", err)
	}

	fmt.Println("  Downloaded installer script. Running...")
	fmt.Println()

	cmd := exec.Command(tmpFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func verifyInstallerChecksum(script []byte) error {
	checksumResp, err := httpClient.Get(installerChecksumURL)
	if err != nil {
		fmt.Println("  ⚠ Could not fetch checksum — skipping verification")
		return nil
	}
	defer checksumResp.Body.Close() //nolint:errcheck

	if checksumResp.StatusCode != http.StatusOK {
		fmt.Println("  ⚠ Checksum file not found — skipping verification")
		return nil
	}

	expectedBytes, err := io.ReadAll(checksumResp.Body)
	if err != nil {
		return fmt.Errorf("read checksum: %w", err)
	}
	expected := strings.TrimSpace(strings.Fields(string(expectedBytes))[0])

	hash := sha256.Sum256(script)
	actual := hex.EncodeToString(hash[:])

	if actual != expected {
		return fmt.Errorf("installer checksum mismatch:\n  expected: %s\n  actual:   %s\nAborting for safety.", expected, actual)
	}
	fmt.Println("  ✓ Checksum verified")
	return nil
}
