//go:build linux

package fix

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/store"
)

func newTempStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir + "/state.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestDetect_NoMatchBlock(t *testing.T) {
	// A finding whose rule is not SSH should return an empty list.
	f := model.Finding{RuleID: "docker.container.runs_as_root"}
	if got := Detect(f); len(got) != 0 {
		t.Errorf("Detect(docker) = %v, want empty", got)
	}
}

func TestDetect_SSHMatchBlock(t *testing.T) {
	// We can't read /etc/ssh/sshd_config on every host, so we
	// point the scan at a temp file with a Match block.
	dir := t.TempDir()
	main := dir + "/sshd_config"
	body := "PermitRootLogin no\n" +
		"Match User alice\n" +
		"  PermitRootLogin yes\n" +
		"}\n"
	if err := writeFile(main, body); err != nil {
		t.Fatal(err)
	}
	// Patch the detector to read from our temp dir.
	prevMain := "/etc/ssh/sshd_config"
	sshMainPath = main
	t.Cleanup(func() { sshMainPath = prevMain })

	f := model.Finding{RuleID: "ssh.permit_root_login.allow"}
	conflicts := Detect(f)
	if len(conflicts) == 0 {
		t.Fatalf("expected at least one conflict from the Match block, got none")
	}
	if conflicts[0].Kind != ConflictSSHMatchBlock {
		t.Errorf("Kind = %q, want %q", conflicts[0].Kind, ConflictSSHMatchBlock)
	}
	if !strings.Contains(conflicts[0].Snippet, "Match User alice") {
		t.Errorf("Snippet = %q, want it to contain the Match block", conflicts[0].Snippet)
	}
}

func TestRenderPreview(t *testing.T) {
	f := model.Finding{
		RuleID:  "ssh.permit_root_login.allow",
		Title:   "Root login is allowed over SSH",
		EntityRefs: []model.EntityRef{
			{Kind: model.EntityRefKindSetting, Display: "PermitRootLogin = yes"},
		},
	}
	p := RenderPreview(f)
	if p.Title == "" {
		t.Errorf("Preview.Title is empty")
	}
	if len(p.Lines) == 0 {
		t.Fatalf("Preview.Lines is empty")
	}
	if !strings.Contains(p.String(), "PermitRootLogin no") {
		t.Errorf("Preview.String() = %q, want to contain 'PermitRootLogin no'", p.String())
	}
}

func TestRenderPreview_UnknownRule(t *testing.T) {
	f := model.Finding{
		RuleID:  "docker.container.runs_as_root",
		Title:   "Container runs as root",
		EntityRefs: []model.EntityRef{
			{Kind: model.EntityRefKindContainerImage, Display: "nginx:1.25.3"},
		},
	}
	p := RenderPreview(f)
	if len(p.Lines) == 0 {
		t.Errorf("Preview.Lines is empty for unknown rule")
	}
}

func TestBackup_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := dir + "/original.txt"
	original := []byte("hello, world\nthis is the original content\n")
	if err := writeFile(src, string(original)); err != nil {
		t.Fatal(err)
	}
	bp, err := CreateBackup(dir+"/backups", src)
	if err != nil {
		t.Fatalf("CreateBackup: %v", err)
	}
	if bp.Full == "" {
		t.Fatal("bp.Full empty")
	}
	// Round-trip: modify the file, restore from backup, verify
	// byte-identical.
	if err := writeFile(src, "modified content\n"); err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackup(bp, src); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	got, err := readFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("after restore, content = %q, want %q", got, original)
	}
	if err := VerifyByteIdentical(bp, src); err != nil {
		t.Errorf("VerifyByteIdentical: %v", err)
	}
}

func TestApply_NoConflict_RecordsFix(t *testing.T) {
	s := newTempStore(t)
	// Seed a host + scan_run + finding.
	host := model.Host{
		ID: "h1", Hostname: "t", OSFamily: "other", Kernel: "k", Arch: "amd64",
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC(),
	}
	if err := s.InsertHostByID(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	run := &model.ScanRun{
		ID: "r1", HostID: host.ID, StartedAt: time.Now().UTC(),
		Status: model.ScanRunRunning, HostveilVersion: "v3.0.0",
	}
	if err := s.InsertScanRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	// Create a real source file so the backup succeeds.
	dir := t.TempDir()
	src := dir + "/sshd_config"
	if err := writeFile(src, "PermitRootLogin yes\n"); err != nil {
		t.Fatal(err)
	}
	f := model.Finding{
		ID: "f1", RuleID: "ssh.permit_root_login.allow",
		Category: model.CategorySSH, Severity: model.SeverityHigh,
		Title: "Root login is allowed over SSH",
		EntityRefs: []model.EntityRef{
			{Kind: model.EntityRefKindConfigFile, Display: src},
			{Kind: model.EntityRefKindSetting, Display: "PermitRootLogin = yes"},
		},
	}
	if err := s.InsertFindings(context.Background(), run.ID, []model.Finding{f}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	res, err := Apply(s, run.ID, f.ID, f, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.FixRecord.ID == "" {
		t.Error("FixRecord.ID empty")
	}
	if res.FixRecord.BackupPath == "" {
		t.Error("FixRecord.BackupPath empty")
	}
	// Rollback
	rr, err := Rollback(s, res.FixRecord.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rr.FollowUp.RolledBackVia != res.FixRecord.ID {
		t.Errorf("RolledBackVia = %q, want %q", rr.FollowUp.RolledBackVia, res.FixRecord.ID)
	}
}

func TestApply_NoBackupForNonFileFinding(t *testing.T) {
	s := newTempStore(t)
	host := model.Host{ID: "h1", Hostname: "t", OSFamily: "other", Kernel: "k", Arch: "amd64",
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
	if err := s.InsertHostByID(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	run := &model.ScanRun{ID: "r1", HostID: host.ID, StartedAt: time.Now().UTC(),
		Status: model.ScanRunRunning, HostveilVersion: "v3.0.0"}
	if err := s.InsertScanRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	f := model.Finding{
		ID: "f1", RuleID: "image_cve.nginx_known_cve",
		Category: model.CategoryImageCVE, Severity: model.SeverityHigh,
		Title: "nginx:1.25.3 has 4 known CVEs",
		EntityRefs: []model.EntityRef{
			{Kind: model.EntityRefKindContainerImage, Display: "nginx:1.25.3"},
		},
	}
	if err := s.InsertFindings(context.Background(), run.ID, []model.Finding{f}); err != nil {
		t.Fatalf("InsertFindings: %v", err)
	}
	res, err := Apply(s, run.ID, f.ID, f, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("Apply (no backup expected): %v", err)
	}
	if res.FixRecord.BackupPath != "" {
		t.Errorf("BackupPath = %q, want empty for non-file finding", res.FixRecord.BackupPath)
	}
}

// writeFile and readFile are tiny helpers to keep the test
// file free of os.ReadFile / os.WriteFile boilerplate.
func writeFile(p, content string) error {
	return osWriteFile(p, content, 0o644)
}
func readFile(p string) ([]byte, error) { return osReadFile(p) }

// small shims so we can swap the implementations in tests if we
// need to.
var (
	osWriteFile = func(p, c string, m uint32) error { return osWriteFileReal(p, []byte(c), m) }
	osReadFile  = func(p string) ([]byte, error) { return osReadFileReal(p) }
)
