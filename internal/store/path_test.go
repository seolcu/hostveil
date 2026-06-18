package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_Default(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	wantData := filepath.Join(home, ".local", "share", "hostveil")
	if p.DataDir != wantData {
		t.Errorf("DataDir = %q, want %q", p.DataDir, wantData)
	}
	if p.StateDB != filepath.Join(wantData, "state.db") {
		t.Errorf("StateDB = %q", p.StateDB)
	}
	if p.Reports != filepath.Join(wantData, "reports") {
		t.Errorf("Reports = %q", p.Reports)
	}
}

func TestResolve_XDGOverride(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, "xdg-data")
	cfg := filepath.Join(home, "xdg-cfg")
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("XDG_CONFIG_HOME", cfg)

	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if p.DataDir != filepath.Join(data, "hostveil") {
		t.Errorf("DataDir = %q", p.DataDir)
	}
	if p.ConfigDir != filepath.Join(cfg, "hostveil") {
		t.Errorf("ConfigDir = %q", p.ConfigDir)
	}
}

func TestEnsureDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	p, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if err := p.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs() error = %v", err)
	}
	for _, d := range []string{p.DataDir, p.Reports, p.Backups, p.Logs, p.ConfigDir} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("EnsureDirs() did not create %q", d)
		}
	}
}
