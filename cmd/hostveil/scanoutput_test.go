package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportOutputIsPrivateAndRefusesSymlinks(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := writeReport(path, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("new report mode = %v, want 0600", fi.Mode().Perm())
	}

	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked-report")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(link, []byte("overwrite")); err == nil {
		t.Fatal("writeReport accepted a symlink")
	}
	got, _ := os.ReadFile(victim)
	if string(got) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", got)
	}
}
