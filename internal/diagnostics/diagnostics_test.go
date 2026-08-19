package diagnostics

import (
	"testing"
)

func TestRecordCrashRoundTrips(t *testing.T) {
	dir := t.TempDir()
	rec := NewRecord("v3-dev", "scan", "checker ssh", "boom", []byte("goroutine 1 [running]:\nmain.main()"))
	RecordCrash(dir, rec)

	got, err := Crashes(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].Panic != "boom" || got[0].Command != "scan" || got[0].Where != "checker ssh" {
		t.Errorf("record does not match what was written: %+v", got[0])
	}
}

func TestCrashesOnAnEmptyDirectory(t *testing.T) {
	got, err := Crashes(t.TempDir(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d records from an empty directory, want 0", len(got))
	}
}

// pruneCheckpoints in internal/history has a count cap and an age-based
// floor because a checkpoint is a backup. A crash record is diagnostic
// exhaust, not a backup, so this only has to prove the count cap holds —
// there is no promise about how recently one arrived.
func TestRecordCrashPrunesBeyondTheCap(t *testing.T) {
	dir := t.TempDir()
	for i := range maxRecords + 5 {
		rec := NewRecord("v3-dev", "scan", "checker ssh", i, nil)
		RecordCrash(dir, rec)
	}
	got, err := Crashes(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxRecords {
		t.Errorf("got %d records, want the cap of %d", len(got), maxRecords)
	}
}

func TestCrashesRespectsLimit(t *testing.T) {
	dir := t.TempDir()
	for i := range 5 {
		RecordCrash(dir, NewRecord("v3-dev", "scan", "checker ssh", i, nil))
	}
	got, err := Crashes(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
}

func TestRedactStripsIPsAndHomePaths(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ipv4", "connect refused from 203.0.113.42", "connect refused from <ip>"},
		{"loopback ipv4 kept", "listening on 127.0.0.1:8787", "listening on 127.0.0.1:8787"},
		{"home path", "reading /home/alice/.ssh/config", "reading /home/<user>/.ssh/config"},
		{"macos home path", "reading /Users/bob/Library", "reading /Users/<user>/Library"},
		{"timestamp untouched", "applied at 2026-08-20 15:04:05", "applied at 2026-08-20 15:04:05"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Redact(c.in); got != c.want {
				t.Errorf("Redact(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactStripsRealIPv6(t *testing.T) {
	in := "peer 2001:db8::1 refused the connection"
	got := Redact(in)
	if got == in {
		t.Errorf("Redact did not touch a real IPv6 address: %q", got)
	}
}
