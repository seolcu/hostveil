//go:build linux

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/model"
)

func newTempStoreAt(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSuppression_AddIsSuppressedRemove(t *testing.T) {
	s := newTempStoreAt(t)
	ctx := context.Background()
	host := model.Host{ID: "h1", Hostname: "t", OSFamily: "other", Kernel: "k", Arch: "amd64",
		FirstSeenAt: time.Now().UTC(), LastSeenAt: time.Now().UTC()}
	if err := s.InsertHostByID(ctx, host); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSuppression(ctx, "h1", "ssh.permit_root_login.allow", "tested and ok"); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	got, err := s.IsSuppressed(ctx, "h1", "ssh.permit_root_login.allow")
	if err != nil || !got {
		t.Fatalf("IsSuppressed after add = %v, %v; want true", got, err)
	}
	// Adding the same row again returns ErrSuppressed.
	if err := s.AddSuppression(ctx, "h1", "ssh.permit_root_login.allow", "again"); err != ErrSuppressed {
		t.Errorf("AddSuppression (duplicate) = %v, want ErrSuppressed", err)
	}
	// List
	rows, err := s.ListSuppressions(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Errorf("ListSuppressions = %d, want 1", len(rows))
	}
	// Remove
	if err := s.RemoveSuppression(ctx, "h1", "ssh.permit_root_login.allow"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.IsSuppressed(ctx, "h1", "ssh.permit_root_login.allow")
	if got {
		t.Errorf("IsSuppressed after remove = true, want false")
	}
}
