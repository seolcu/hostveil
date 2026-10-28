package forensic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// host is a fake root filesystem plus a scripted runner. Every command the
// checker runs is scripted to its healthy answer, so each test changes only
// the one thing it is about.
type host struct {
	t    *testing.T
	root string
	r    *checktest.Runner
}

func newHost(t *testing.T) *host {
	t.Helper()
	h := &host{t: t, root: t.TempDir(), r: checktest.New()}
	h.write("/var/log/journal/.keep", "")
	h.write("/etc/rsyslog.d/90-remote.conf", "*.* @@logs.example:514\n")
	h.r.Script("# /etc/systemd/journald.conf\n[Journal]\n", journaldCatConfigArgv...)
	h.r.Script("LoadState=loaded\nActiveState=active\n", auditdShowArgv...)
	h.r.Script("No rules\n", auditctlListArgv...)
	h.r.Script("NTPSynchronized=yes\nNTP=yes\n", timedatectlArgv...)
	h.r.Script("ActiveState=inactive\n", journalUploadArgv...)
	return h
}

func (h *host) write(p, content string) {
	h.t.Helper()
	full := filepath.Join(h.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *host) scan() ([]model.Finding, error) {
	h.t.Helper()
	c := &Checker{Root: h.root}
	return c.Check(context.Background(), platform.Env{ServiceManager: platform.SMSystemd, Runner: h.r})
}

func ids(fs []model.Finding) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range fs {
		out[f.ID] = f
		if err := f.Validate(); err != nil {
			panic(err)
		}
	}
	return out
}

func TestAHealthyHostHasNoFindings(t *testing.T) {
	fs, err := newHost(t).scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("findings on a healthy host: %v", ids(fs))
	}
}

func TestJournalInMemoryIsFlagged(t *testing.T) {
	for name, tc := range map[string]struct {
		conf    string
		journal bool
		want    bool
	}{
		"volatile":                 {"[Journal]\nStorage=volatile\n", true, true},
		"auto without the dir":     {"[Journal]\n", false, true},
		"auto with the dir":        {"[Journal]\n", true, false},
		"persistent without dir":   {"[Journal]\nStorage=persistent\n", false, false},
		"drop-in overrides":        {"[Journal]\nStorage=volatile\n# /etc/systemd/journald.conf.d/50-x.conf\n[Journal]\nStorage=persistent\n", false, false},
		"other section is ignored": {"[Upload]\nStorage=volatile\n[Journal]\n", true, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHost(t)
			if !tc.journal {
				_ = os.RemoveAll(filepath.Join(h.root, "var/log/journal"))
			}
			h.r.Script("# /etc/systemd/journald.conf\n"+tc.conf, journaldCatConfigArgv...)
			fs, _ := h.scan()
			f, got := ids(fs)["forensic.journald-volatile"]
			if got != tc.want {
				t.Fatalf("flagged = %v, want %v", got, tc.want)
			}
			if got && f.Metadata["journald_dropin"] == "" {
				t.Error("no drop-in path for the fix to write")
			}
		})
	}
}

func TestTheDropInSortsAfterEveryLoadedOne(t *testing.T) {
	if got := journaldDropIn([]string{"10-a.conf", "95-z.conf"}); got != JournaldDropInDir+"99-hostveil-forensic.conf" {
		t.Errorf("got %q", got)
	}
	if got := journaldDropIn([]string{"zz.conf"}); got != "" {
		t.Errorf("no name sorts after zz.conf, got %q", got)
	}
}

func TestShortJournalRetentionIsFlagged(t *testing.T) {
	for v, want := range map[string]bool{"2week": true, "1month": true, "30d": true, "3month": false, "1y": false, "0": false, "nonsense": false} {
		h := newHost(t)
		h.r.Script("[Journal]\nMaxRetentionSec="+v+"\n", journaldCatConfigArgv...)
		fs, _ := h.scan()
		if _, got := ids(fs)["forensic.journald-retention"]; got != want {
			t.Errorf("MaxRetentionSec=%s: flagged = %v, want %v", v, got, want)
		}
	}
}

func TestParseTimespan(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90day": 90 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "1h 30min": 90 * time.Minute, "3600": time.Hour,
	} {
		if got, ok := parseTimespan(in); !ok || got != want {
			t.Errorf("%q = %v, %v; want %v", in, got, ok, want)
		}
	}
}

func TestAuditd(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		h := newHost(t)
		h.r.Script("LoadState=not-found\nActiveState=inactive\n", auditdShowArgv...)
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.auditd-missing"]; !ok {
			t.Error("not flagged")
		}
	})
	webHost := func(t *testing.T, rules string) map[string]model.Finding {
		h := newHost(t)
		h.write("/usr/sbin/apache2", "")
		h.write("/etc/passwd", "root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")
		h.r.Script(rules, auditctlListArgv...)
		fs, _ := h.scan()
		return ids(fs)
	}
	t.Run("web server without an exec rule", func(t *testing.T) {
		f, ok := webHost(t, "No rules\n")["forensic.service-exec-unaudited"]
		if !ok || f.Metadata["service_uid"] != "33" || f.Service != "www-data" {
			t.Fatalf("got %+v", f)
		}
	})
	t.Run("an existing rule by uid counts", func(t *testing.T) {
		if _, ok := webHost(t, "-a always,exit -F arch=b64 -S execve -F euid=33 -F key=www-exec\n")["forensic.service-exec-unaudited"]; ok {
			t.Error("flagged despite a rule")
		}
	})
	t.Run("www-data alone is not a web server", func(t *testing.T) {
		h := newHost(t)
		h.write("/etc/passwd", "www-data:x:33:33::/var/www:/usr/sbin/nologin\n")
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.service-exec-unaudited"]; ok {
			t.Error("flagged a host with no web server")
		}
	})
	t.Run("rules unreadable is partial, not clean", func(t *testing.T) {
		h := newHost(t)
		h.write("/usr/sbin/nginx", "")
		h.write("/etc/passwd", "www-data:x:33:33::/var/www:/usr/sbin/nologin\n")
		h.r.Fail(errors.New("permission denied"), auditctlListArgv...)
		_, err := h.scan()
		var pe *check.PartialError
		if !errors.As(err, &pe) {
			t.Fatalf("err = %v, want a PartialError", err)
		}
	})
}

func TestTimeSync(t *testing.T) {
	h := newHost(t)
	h.r.Script("NTPSynchronized=no\nNTP=no\n", timedatectlArgv...)
	fs, _ := h.scan()
	if _, ok := ids(fs)["forensic.time-unsynced"]; !ok {
		t.Error("not flagged")
	}
}

const ubuntuRsyslog = `/var/log/syslog
/var/log/auth.log
{
	rotate 4
	weekly
	missingok
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
`

func TestLogrotate(t *testing.T) {
	h := newHost(t)
	h.write("/etc/logrotate.conf", "weekly\nrotate 4\n")
	h.write("/etc/logrotate.d/rsyslog", ubuntuRsyslog)
	h.write("/etc/logrotate.d/nginx", "/var/log/nginx/*.log {\n\tdaily\n\trotate 120\n}\n")
	fs, _ := h.scan()
	got := 0
	for _, f := range fs {
		if f.ID == "forensic.logrotate-short" {
			got++
			if f.Metadata["logrotate_file"] != "/etc/logrotate.d/rsyslog" {
				t.Errorf("flagged %s", f.Metadata["logrotate_file"])
			}
		}
	}
	if got != 1 {
		t.Errorf("%d logrotate findings, want 1 (rsyslog keeps 35 days, nginx 121)", got)
	}
	if d := ParseLogrotate(ubuntuRsyslog)[0].Days(4, "weekly"); d != 35 {
		t.Errorf("rsyslog keeps %d days, want 35", d)
	}
	if d := (LogrotateBlock{Rotate: RotateFor("weekly"), Period: "weekly"}).Days(0, ""); d < retentionDays {
		t.Errorf("RotateFor(weekly) reaches only %d days", d)
	}
}

func TestWebLogFormats(t *testing.T) {
	t.Run("apache combined has no request size", func(t *testing.T) {
		h := newHost(t)
		h.write("/etc/apache2/apache2.conf", `LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined`+"\n")
		h.write("/etc/apache2/sites-enabled/000-default.conf", "CustomLog ${APACHE_LOG_DIR}/access.log combined\n")
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.weblog-no-size"]; !ok {
			t.Error("not flagged")
		}
	})
	t.Run("apache with %I is fine", func(t *testing.T) {
		h := newHost(t)
		h.write("/etc/apache2/apache2.conf", `LogFormat "%h %t \"%r\" %>s %I %O %D" forensic`+"\nCustomLog /var/log/apache2/access.log forensic\n")
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.weblog-no-size"]; ok {
			t.Error("flagged a format with %I")
		}
	})
	t.Run("nginx default access log", func(t *testing.T) {
		h := newHost(t)
		h.write("/etc/nginx/nginx.conf", "http {\n  server { listen 80; }\n}\n")
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.weblog-no-size"]; !ok {
			t.Error("not flagged")
		}
	})
	t.Run("nginx with request_length", func(t *testing.T) {
		h := newHost(t)
		h.write("/etc/nginx/nginx.conf", "http {\n  log_format f '$remote_addr [$time_local] \"$request\" $status $request_length $request_time';\n  access_log /var/log/nginx/access.log f;\n}\n")
		fs, _ := h.scan()
		if _, ok := ids(fs)["forensic.weblog-no-size"]; ok {
			t.Error("flagged a format with $request_length")
		}
	})
}

func TestRemoteLog(t *testing.T) {
	h := newHost(t)
	_ = os.Remove(filepath.Join(h.root, "etc/rsyslog.d/90-remote.conf"))
	h.write("/etc/rsyslog.conf", "# *.* @@commented.example\nauth.* /var/log/auth.log\n")
	fs, _ := h.scan()
	if _, ok := ids(fs)["forensic.no-remote-log"]; !ok {
		t.Error("not flagged")
	}
	h.r.Script("ActiveState=active\n", journalUploadArgv...)
	fs, _ = h.scan()
	if _, ok := ids(fs)["forensic.no-remote-log"]; ok {
		t.Error("flagged despite journal-upload")
	}
}
