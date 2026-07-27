package platform

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadFileNoFollowReadsARegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileNoFollow(p, 1<<20)
	if err != nil {
		t.Fatalf("ReadFileNoFollow: %v", err)
	}
	if string(b) != `{"ok":true}` {
		t.Errorf("read %q", b)
	}
}

func TestReadFileNoFollowRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileNoFollow(link, 1<<20); err == nil {
		t.Fatal("a symlink must be refused, not followed")
	}
}

// The FIFO case is the one that used to hang: open(2) on a FIFO with no
// writer blocks until one appears, which for an attacker's FIFO is never.
// The read runs in a goroutine so a regression shows up as a test failure
// with a message rather than a suite that never finishes.
func TestReadFileNoFollowDoesNotBlockOnAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFileNoFollow(p, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be an error, not content")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("error should name the file type: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFileNoFollow blocked on a FIFO")
	}
}

func TestReadFileNoFollowCapsTheSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(p, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileNoFollow(p, 99); err == nil {
		t.Fatal("a file over the limit must be an error, not a truncated read")
	}
	if b, err := ReadFileNoFollow(p, 100); err != nil || len(b) != 100 {
		t.Fatalf("a file exactly at the limit must read whole: %d bytes, %v", len(b), err)
	}
}

func TestChmodNoFollowChangesARegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ChmodNoFollow(p, 0o600); err != nil {
		t.Fatalf("ChmodNoFollow: %v", err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %#o, want 0600", fi.Mode().Perm())
	}
}

func TestChmodNoFollowRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := ChmodNoFollow(link, 0o600); err == nil {
		t.Fatal("a symlink must be refused, not chmod'ed through")
	}
	fi, _ := os.Stat(victim)
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("the symlink's target changed mode to %#o — the chmod followed the link", fi.Mode().Perm())
	}
}
