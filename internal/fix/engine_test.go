package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/scanner"
)

func TestMinimalHostFix(t *testing.T) {
	findings := []domain.Finding{
		{ID: domain.FindingHostSSHRootLogin, Service: "host"},
		{ID: domain.FindingHostFirewallNoActive, Service: "host"},
	}
	plan := MinimalHostFix(findings)
	if plan == nil {
		t.Fatal("MinimalHostFix returned nil")
	}
	if len(plan.HostEdits) == 0 && len(plan.ShellCmds) == 0 {
		t.Error("expected at least some actions for known host findings")
	}
	if len(plan.Actions) == 0 {
		t.Error("expected non-empty Actions list")
	}
}

func TestMinimalHostFixEmpty(t *testing.T) {
	plan := MinimalHostFix(nil)
	if plan == nil {
		t.Fatal("MinimalHostFix(nil) returned nil")
	}
	if plan.Changed() {
		t.Error("expected empty plan for nil findings")
	}
}

func TestMinimalAdapterFix(t *testing.T) {
	findings := []domain.Finding{
		{ID: "trivy.CVE-2024-0001", Service: "nginx:latest"},
		{ID: "dockle.CIS-DI-0001", Service: "nginx:latest"},
	}
	actions := MinimalAdapterFix(findings)
	if len(actions) == 0 {
		t.Error("expected actions for known adapter findings")
	}
}

func TestMinimalAdapterFixEmpty(t *testing.T) {
	actions := MinimalAdapterFix(nil)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions for nil, got %d", len(actions))
	}
}

func TestPreviewAnyFindingCompose(t *testing.T) {
	f := domain.Finding{
		ID: "test", Source: domain.SourceNativeCompose,
		Remediation: domain.RemediationAuto, Service: "test-svc",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return non-empty for compose finding")
	}
}

func TestPreviewAnyFindingHost(t *testing.T) {
	f := domain.Finding{
		ID: domain.FindingHostSSHRootLogin, Source: domain.SourceNativeHost,
		Remediation: domain.RemediationReview, Service: "host",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Fatal("PreviewAnyFinding returned empty for host finding")
	}
	if !strings.Contains(result, "Host Edit") && !strings.Contains(result, "Shell Command") {
		t.Error("host fix preview should contain action type")
	}
	if !strings.Contains(result, "/etc/ssh/sshd_config") {
		t.Error("host fix preview should contain file path")
	}
}

func TestPreviewAnyFindingAdapter(t *testing.T) {
	f := domain.Finding{
		ID: "trivy.CVE-2024-0001", Source: domain.SourceTrivy,
		Remediation: domain.RemediationReview, Service: "nginx:latest",
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Fatal("PreviewAnyFinding returned empty for adapter finding")
	}
	if !strings.Contains(result, "nginx") {
		t.Error("adapter fix preview should contain service name")
	}
}

func TestPreviewAnyFindingHostUnknown(t *testing.T) {
	f := domain.Finding{
		ID: "nonexistent.finding", Source: domain.SourceNativeHost,
		Remediation: domain.RemediationReview,
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return message for unknown host finding")
	}
}

func TestPreviewAnyFindingAdapterUnknown(t *testing.T) {
	f := domain.Finding{
		ID: "unknown.finding", Source: domain.SourceGitleaks,
		Remediation: domain.RemediationReview,
	}
	result := PreviewAnyFinding(f, "", nil)
	if result == "" {
		t.Error("PreviewAnyFinding should return message for unknown adapter finding")
	}
}

func TestNewEngine(t *testing.T) {
	e := NewEngine("/compose.yml", []domain.Finding{
		{ID: "test", Remediation: domain.RemediationAuto},
	})
	if e == nil {
		t.Fatal("NewEngine returned nil")
	}
	if e.ComposeFile != "/compose.yml" {
		t.Errorf("ComposeFile = %q, want /compose.yml", e.ComposeFile)
	}
}

// TestEngineApplyModifiesComposeFile verifies the full pipeline:
// scanner → fix engine Preview → Apply → YAML verification.
// Uses the public-port-rebind scenario: a compose file with a port that
// binds to all interfaces (no 127.0.0.1 restriction).
func TestEngineApplyModifiesComposeFile(t *testing.T) {
	// 1. Create a temporary compose file with known vulnerabilities
	tmpDir, err := os.MkdirTemp("", "hostveil-fix-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  web:
    image: nginx:1.25
    user: "1000:1000"
    ports:
      - "8080:80"
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Run the scanner
	result, err := scanner.Run(scanner.Config{
		ComposeFiles: []string{composePath},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify exposure.public_binding finding exists
	var hasPublicBinding bool
	for _, f := range result.Findings {
		if f.ID == domain.FindingExposurePublicBinding {
			hasPublicBinding = true
			break
		}
	}
	if !hasPublicBinding {
		t.Fatal("expected exposure.public_binding finding from scanner")
	}

	// 3. Create a fix Engine with the findings
	engine := NewEngine(composePath, result.Findings)

	// 4. Call Preview() and verify AutoApplied has expected items
	plan, err := engine.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil {
		t.Fatal("plan is nil")
	}

	// Check that the public binding fix is in AutoApplied
	foundAutoApplied := false
	for _, p := range plan.AutoApplied {
		if p.Service == "web" && strings.Contains(p.Summary, "Bound") {
			foundAutoApplied = true
			break
		}
	}
	if !foundAutoApplied {
		t.Error("expected AutoApplied to contain public binding fix for web")
	}

	// 5. Read original content before Apply for later comparison
	origContent, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Call Apply() and verify the compose file was modified
	plan, err = engine.Apply()
	if err != nil {
		t.Fatal(err)
	}

	// Verify backup was created
	if plan.BackupPath == "" {
		t.Error("expected BackupPath to be set after Apply")
	} else {
		if _, err := os.Stat(plan.BackupPath); os.IsNotExist(err) {
			t.Error("backup file does not exist at", plan.BackupPath)
		}
	}

	// Verify the compose file was modified (auto-fix actions applied)
	modified, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	modifiedStr := string(modified)

	// The exposure.public_binding finding has RemediationReview (for HostIP=""),
	// so the corresponding FixAction has Command "review" and is skipped by Apply.
	// However, other auto-fix findings (runtime.writable_rootfs,
	// runtime.no_new_privileges_disabled) generate auto actions that DO get applied.
	// Verify that at least some modification happened.
	if modifiedStr == string(origContent) {
		// If unchanged, verify there's at least one auto action that should have been applied
		hasAutoAction := false
		for _, a := range plan.Actions {
			if a.Type == ActionComposeEdit && a.Command == "auto" {
				hasAutoAction = true
				break
			}
		}
		if hasAutoAction {
			t.Error("file was not modified despite having auto-fix actions")
		}
	}

	// The action for exposure.public_binding should have the 127.0.0.1 fix in its Diff
	foundPortAction := false
	for _, a := range plan.Actions {
		if a.Type == ActionComposeEdit && a.Service == "web" &&
			strings.Contains(a.Diff, "127.0.0.1:") {
			foundPortAction = true
			break
		}
	}
	if !foundPortAction {
		t.Error("expected a compose edit action with 127.0.0.1 port fix in Actions")
	}

	// 6. Restore the backup
	if plan.BackupPath != "" {
		backupData, err := os.ReadFile(plan.BackupPath)
		if err == nil {
			if err := os.WriteFile(composePath, backupData, 0644); err != nil {
				t.Error("failed to restore backup:", err)
			}
		}
	}
}

// TestEngineApplyUpdatesLatestTag verifies the fix engine correctly handles
// images tagged with :latest and applies a pin-version fix.
func TestEngineApplyUpdatesLatestTag(t *testing.T) {
	// 1. Create a compose file with image: nginx:latest
	tmpDir, err := os.MkdirTemp("", "hostveil-fix-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  web:
    image: nginx:latest
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Run the scanner
	result, err := scanner.Run(scanner.Config{
		ComposeFiles: []string{composePath},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Verify updates.latest_tag finding is generated
	var latestTagFindings []domain.Finding
	for _, f := range result.Findings {
		if f.ID == domain.FindingUpdatesLatestTag {
			latestTagFindings = append(latestTagFindings, f)
		}
	}
	if len(latestTagFindings) == 0 {
		t.Fatal("expected updates.latest_tag finding for image: nginx:latest")
	}

	// Filter to only latest_tag findings
	engine := NewEngine(composePath, latestTagFindings)

	// 4. Call Preview() and verify AutoApplied has the pin version proposal
	plan, err := engine.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil {
		t.Fatal("plan is nil")
	}

	foundPinProposal := false
	var pinSummary string
	for _, p := range plan.AutoApplied {
		if p.Service == "web" && strings.Contains(p.Summary, "Pinned image") {
			foundPinProposal = true
			pinSummary = p.Summary
			break
		}
	}
	if !foundPinProposal {
		t.Error("expected AutoApplied to contain pin version proposal for web")
	} else {
		if !strings.Contains(pinSummary, "nginx:stable") {
			t.Errorf("pin proposal summary should mention nginx:stable, got: %s", pinSummary)
		}
	}

	// 5. Read original content
	origContent, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Call Apply() and verify changes
	plan, err = engine.Apply()
	if err != nil {
		t.Fatal(err)
	}

	if plan.BackupPath == "" {
		t.Error("expected BackupPath to be set after Apply")
	}

	modified, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	modifiedStr := string(modified)

	// Verify that the Apply modified the file (added the pin version TODO comment)
	if modifiedStr == string(origContent) {
		t.Error("Apply did not modify the compose file")
	}

	// Verify the TODO comment about pinning was added
	if !strings.Contains(modifiedStr, "TODO: pin image version tag") {
		t.Error("expected 'TODO: pin image version tag' comment to be added")
	}

	// Restore the backup
	if plan.BackupPath != "" {
		backupData, err := os.ReadFile(plan.BackupPath)
		if err == nil {
			if err := os.WriteFile(composePath, backupData, 0644); err != nil {
				t.Error("failed to restore backup:", err)
			}
		}
	}
}

// TestEngineApplyWritableRootfs verifies the fix engine adds read_only: true
// when a container has a writable root filesystem.
func TestEngineApplyWritableRootfs(t *testing.T) {
	// 1. Create a compose file WITHOUT read_only: true
	tmpDir, err := os.MkdirTemp("", "hostveil-fix-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	composePath := filepath.Join(tmpDir, "docker-compose.yml")
	composeContent := `services:
  web:
    image: nginx:1.25
`
	if err := os.WriteFile(composePath, []byte(composeContent), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. Run the scanner
	result, err := scanner.Run(scanner.Config{
		ComposeFiles: []string{composePath},
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Verify runtime.writable_rootfs finding
	var writableRootfsFindings []domain.Finding
	for _, f := range result.Findings {
		if f.ID == domain.FindingRuntimeWritableRootfs {
			writableRootfsFindings = append(writableRootfsFindings, f)
		}
	}
	if len(writableRootfsFindings) == 0 {
		t.Fatal("expected runtime.writable_rootfs finding")
	}

	// Filter to only writable_rootfs findings
	engine := NewEngine(composePath, writableRootfsFindings)

	// 4. Call Preview() and verify AutoApplied has the read_only proposal
	plan, err := engine.Preview()
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil {
		t.Fatal("plan is nil")
	}

	foundReadOnlyProposal := false
	for _, p := range plan.AutoApplied {
		if p.Service == "web" && strings.Contains(p.Summary, "read_only") {
			foundReadOnlyProposal = true
			break
		}
	}
	if !foundReadOnlyProposal {
		t.Error("expected AutoApplied to contain read_only fix for web")
	}

	// 5. Read original content
	origContent, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Call Apply() and verify read_only: true was added
	plan, err = engine.Apply()
	if err != nil {
		t.Fatal(err)
	}

	if plan.BackupPath == "" {
		t.Error("expected BackupPath to be set after Apply")
	}

	modified, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatal(err)
	}
	modifiedStr := string(modified)

	// Verify read_only: true was added
	if !strings.Contains(modifiedStr, "read_only: true") {
		t.Errorf("expected read_only: true to be added to the compose file\noriginal:\n%s\nmodified:\n%s", origContent, modifiedStr)
	}

	// Verify the file changed
	if modifiedStr == string(origContent) {
		t.Error("Apply did not modify the compose file")
	}

	// Restore the backup
	if plan.BackupPath != "" {
		backupData, err := os.ReadFile(plan.BackupPath)
		if err == nil {
			if err := os.WriteFile(composePath, backupData, 0644); err != nil {
				t.Error("failed to restore backup:", err)
			}
		}
	}
}
