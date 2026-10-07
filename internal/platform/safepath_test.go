package platform

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The Beneath family exists for one situation: hostveil running as root on a
// path the audited account owns every component of. Each test below is a
// shape that account can leave lying around, and the assertion is always
// about what happened outside root, because that is the damage.

func TestBeneathRefusesATargetOutsideRoot(t *testing.T) {
	root := t.TempDir()
	for _, target := range []string{
		root,                                 // the root itself is not a file beneath it
		filepath.Dir(root),                   // ..
		filepath.Join(root, "..", "x"),       // ../x after cleaning
		filepath.Join(root, "a", "..", ".."), // climbs back out through a component
		"/etc/passwd",                        // somewhere else entirely
	} {
		if _, err := ReadFileBeneath(root, target, 1<<20); err == nil {
			t.Errorf("ReadFileBeneath(%q) succeeded; want refused", target)
		}
		if _, err := StatBeneath(root, target); err == nil {
			t.Errorf("StatBeneath(%q) succeeded; want refused", target)
		}
		if err := ChmodBeneath(root, target, 0o600); err == nil {
			t.Errorf("ChmodBeneath(%q) succeeded; want refused", target)
		}
		if err := RemoveBeneath(root, target); err == nil {
			t.Errorf("RemoveBeneath(%q) succeeded; want refused", target)
		}
	}
}

// A symlink as the last component is the simplest redirect there is: the
// account replaces its config with a link to /etc/shadow and waits for root
// to read or chmod it.
func TestBeneathRefusesASymlinkAsTheFinalComponent(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "config")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFileBeneath(root, link, 1<<20); err == nil {
		t.Fatalf("ReadFileBeneath followed the final symlink and read %q", b)
	}
	if _, err := StatBeneath(root, link); err == nil {
		t.Fatal("StatBeneath followed the final symlink")
	}
	if err := ChmodBeneath(root, link, 0o644); err == nil {
		t.Fatal("ChmodBeneath followed the final symlink")
	}
	if fi, err := os.Stat(outside); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("outside file mode = %v (%v), want unchanged 0600", fi.Mode().Perm(), err)
	}
}

// The root is the one component allowed to be a link: a home directory
// relocated with a symlink is ordinary, and refusing it would make every
// finding under that home unreadable.
func TestBeneathFollowsASymlinkedRoot(t *testing.T) {
	realHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(realHome, "config"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(realHome, root); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileBeneath(root, filepath.Join(root, "config"), 1<<20)
	if err != nil || string(b) != "ok" {
		t.Fatalf("ReadFileBeneath through a symlinked root = %q, %v; want \"ok\"", b, err)
	}
}

func TestReadFileBeneathReadsANestedFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".config", "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileBeneath(root, p, 1<<20)
	if err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("ReadFileBeneath = %q, %v", b, err)
	}
}

func TestReadFileBeneathCapsTheSize(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "big")
	if err := os.WriteFile(p, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileBeneath(root, p, 99); err == nil {
		t.Fatal("a file over the limit must be an error, not a truncated read")
	}
	if b, err := ReadFileBeneath(root, p, 100); err != nil || len(b) != 100 {
		t.Fatalf("a file exactly at the limit must read whole: %d bytes, %v", len(b), err)
	}
}

func TestReadFileBeneathDoesNotBlockOnAFIFO(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "config")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFileBeneath(root, p, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a FIFO must be refused by type, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFileBeneath blocked on a FIFO")
	}
}

func TestChmodBeneathChangesAFileAndADirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "creds")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{file: 0o600, dir: 0o700} {
		if err := ChmodBeneath(root, path, mode); err != nil {
			t.Fatalf("ChmodBeneath(%s): %v", path, err)
		}
		if fi, _ := os.Stat(path); fi.Mode().Perm() != mode {
			t.Errorf("%s mode = %#o, want %#o", path, fi.Mode().Perm(), mode)
		}
	}
}

func TestChmodBeneathRefusesAFIFO(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := ChmodBeneath(root, p, 0o600); err == nil {
		t.Fatal("a FIFO must be refused, not chmod'ed")
	}
}

func TestStatBeneathReportsTheFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "f")
	if err := os.WriteFile(p, []byte("abc"), 0o640); err != nil {
		t.Fatal(err)
	}
	fi, err := StatBeneath(root, p)
	if err != nil {
		t.Fatalf("StatBeneath: %v", err)
	}
	if fi.Size() != 3 || fi.Mode().Perm() != 0o640 {
		t.Errorf("StatBeneath = size %d mode %#o, want 3 0640", fi.Size(), fi.Mode().Perm())
	}
}

func TestRemoveBeneathRemovesTheFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sub", "f")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBeneath(root, p); err != nil {
		t.Fatalf("RemoveBeneath: %v", err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("file still present after RemoveBeneath: %v", err)
	}
}

// unlink never follows the name it is given, so a final symlink is removed
// as a link. What must not happen is the target going with it.
func TestRemoveBeneathRemovesASymlinkNotItsTarget(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBeneath(root, link); err != nil {
		t.Fatalf("RemoveBeneath: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the symlink's target was removed: %v", err)
	}
}

func TestRemoveBeneathRefusesASymlinkInAParentComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	victim := filepath.Join(outside, "config")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "runtime")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveBeneath(root, filepath.Join(root, "runtime", "config")); err == nil {
		t.Fatal("RemoveBeneath walked through a symlinked parent")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("a file outside root was removed: %v", err)
	}
}

// ReadFileBounded is the opposite policy on links — system configuration
// legitimately uses them — and the same policy on everything else.
func TestReadFileBoundedFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sysctl.conf")
	if err := os.WriteFile(target, []byte("net.ipv4.ip_forward=0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "99-sysctl.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFileBounded(link, 1<<20)
	if err != nil || string(b) != "net.ipv4.ip_forward=0\n" {
		t.Fatalf("ReadFileBounded through a symlink = %q, %v", b, err)
	}
}

func TestReadFileBoundedCapsTheSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(p, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileBounded(p, 99); err == nil {
		t.Fatal("a file over the limit must be an error, not a truncated read")
	}
	if b, err := ReadFileBounded(p, 100); err != nil || len(b) != 100 {
		t.Fatalf("a file exactly at the limit must read whole: %d bytes, %v", len(b), err)
	}
	if _, err := ReadFileBounded(p, -1); err == nil {
		t.Fatal("a negative limit must be an error, not an unbounded read")
	}
}

func TestReadFileBoundedDoesNotBlockOnAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFileBounded(p, 1<<20)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO must be an error, not content")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFileBounded blocked on a FIFO")
	}
}

// Chowning to the caller's own ids is the one ownership change an
// unprivileged test can make, and it still exercises the whole path.
func TestChownNoFollowChangesARegularFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ChownNoFollow(p, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("ChownNoFollow: %v", err)
	}
}

func TestChownNoFollowRefusesASymlinkAndADirectory(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := ChownNoFollow(link, os.Getuid(), os.Getgid()); err == nil {
		t.Error("a symlink must be refused, not chowned through")
	}
	if err := ChownNoFollow(dir, os.Getuid(), os.Getgid()); err == nil {
		t.Error("a directory must be refused; only a created output file is chowned")
	}
}
