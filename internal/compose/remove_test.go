package compose

import (
	"strings"
	"testing"
)

// The source every removal test edits. The comments and the blank line are
// what a full re-encode would disturb, so an output that still carries them
// exactly is one that went through the minimal text edit.
const removalSrc = `services:
  # the media server
  app:
    image: myapp   # pinned below
    privileged: true
    network_mode: host
    pid: host
    cap_add:
      - NET_ADMIN
      - CAP_SYS_ADMIN
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host/etc
      - data:/data:rw

  db:
    image: postgres
`

// without returns removalSrc with the given lines deleted, which is what a
// minimal removal must produce byte for byte.
func without(t *testing.T, lines ...string) string {
	t.Helper()
	out := removalSrc
	for _, l := range lines {
		if !strings.Contains(out, l+"\n") {
			t.Fatalf("fixture has no line %q", l)
		}
		out = strings.Replace(out, l+"\n", "", 1)
	}
	return out
}

func render(t *testing.T, d *Doc) string {
	t.Helper()
	out, err := d.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return string(out)
}

func TestRemoveKeyIsAOneLineDiff(t *testing.T) {
	for _, key := range []string{"privileged", "network_mode", "pid"} {
		d := loadOrFail(t, removalSrc)
		if err := d.RemoveKey("app", key); err != nil {
			t.Fatalf("RemoveKey(%s): %v", key, err)
		}
		line := map[string]string{
			"privileged":   "    privileged: true",
			"network_mode": "    network_mode: host",
			"pid":          "    pid: host",
		}[key]
		if got, want := render(t, d), without(t, line); got != want {
			t.Errorf("RemoveKey(%s):\n got:\n%s\nwant:\n%s", key, got, want)
		}
	}
}

func TestRemoveKeyTakesItsWholeBlock(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveKey("app", "cap_add"); err != nil {
		t.Fatal(err)
	}
	want := without(t, "    cap_add:", "      - NET_ADMIN", "      - CAP_SYS_ADMIN")
	if got := render(t, d); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoveKeyThatIsNotThereIsAnError(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveKey("db", "privileged"); err == nil {
		t.Fatal("removing an absent key must be an error: the finding said it was there")
	}
	if err := d.RemoveKey("nope", "privileged"); err == nil {
		t.Fatal("an unknown service must be an error")
	}
}

func TestRemoveCapAddMatchesWithOrWithoutThePrefix(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveCapAdd("app", "SYS_ADMIN"); err != nil {
		t.Fatal(err)
	}
	if got, want := render(t, d), without(t, "      - CAP_SYS_ADMIN"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// Taking the last item out leaves the key with nothing under it, which reads
// back as null. Removing the key with it is the edit the author would make.
func TestRemovingTheLastItemRemovesTheKey(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveCapAdd("app", "NET_ADMIN"); err != nil {
		t.Fatal(err)
	}
	if err := d.RemoveCapAdd("app", "SYS_ADMIN"); err != nil {
		t.Fatal(err)
	}
	proj, err := Parse("x.yml", []byte(render(t, d)))
	if err != nil {
		t.Fatalf("edited file no longer parses: %v", err)
	}
	if caps := proj.Services["app"].CapAdd; len(caps) != 0 {
		t.Errorf("cap_add = %v, want gone", caps)
	}
}

func TestRemoveSecurityOpt(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveSecurityOpt("app", "seccomp: unconfined"); err != nil {
		t.Fatal(err)
	}
	if got, want := render(t, d), without(t, "      - seccomp:unconfined"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRemoveVolumeBySource(t *testing.T) {
	d := loadOrFail(t, removalSrc)
	if err := d.RemoveVolume("app", "/var/run/docker.sock"); err != nil {
		t.Fatal(err)
	}
	if got, want := render(t, d), without(t, "      - /var/run/docker.sock:/var/run/docker.sock"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetVolumeReadOnly(t *testing.T) {
	for _, tc := range []struct{ source, before, after string }{
		{"/etc/", "/etc:/host/etc", "/etc:/host/etc:ro"},
		{"data", "data:/data:rw", "data:/data:ro"},
	} {
		d := loadOrFail(t, removalSrc)
		if err := d.SetVolumeReadOnly("app", tc.source); err != nil {
			t.Fatalf("%s: %v", tc.source, err)
		}
		want := strings.Replace(removalSrc, "- "+tc.before+"\n", "- "+tc.after+"\n", 1)
		if got := render(t, d); got != want {
			t.Errorf("%s:\n got:\n%s\nwant:\n%s", tc.source, got, want)
		}
	}
}

func TestShortVolumeReadOnlyKeepsOtherOptions(t *testing.T) {
	for in, want := range map[string]string{
		"/etc:/e":         "/etc:/e:ro",
		"/etc:/e:rw":      "/etc:/e:ro",
		"/etc:/e:ro":      "/etc:/e:ro",
		"/etc:/e:rw,z":    "/etc:/e:ro,z",
		"/etc:/e:rshared": "/etc:/e:ro,rshared",
	} {
		if got := shortVolumeReadOnly(in); got != want {
			t.Errorf("shortVolumeReadOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetVolumeReadOnlyOnTheLongForm(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: x\n    volumes:\n      - type: bind\n        source: /etc\n        target: /host/etc\n")
	if err := d.SetVolumeReadOnly("app", "/etc"); err != nil {
		t.Fatal(err)
	}
	proj, err := Parse("x.yml", []byte(render(t, d)))
	if err != nil {
		t.Fatalf("edited file no longer parses: %v", err)
	}
	if v := proj.Services["app"].Volumes; len(v) != 1 || !v[0].ReadOnly {
		t.Errorf("volumes = %+v, want the one mount read-only", v)
	}
}

func TestSetReadOnlyRootfsInsertsBothKeysTogether(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: x   # keep me\n\n  db:\n    image: y\n")
	if err := d.SetReadOnlyRootfs("app", []string{"/tmp", "/run"}); err != nil {
		t.Fatal(err)
	}
	want := "services:\n  app:\n    image: x   # keep me\n    read_only: true\n    tmpfs:\n      - /tmp\n      - /run\n\n  db:\n    image: y\n"
	if got := render(t, d); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSetReadOnlyRootfsAddsToAnExistingTmpfs(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: x\n    tmpfs:\n      - /cache\n")
	if err := d.SetReadOnlyRootfs("app", []string{"/tmp"}); err != nil {
		t.Fatal(err)
	}
	proj, err := Parse("x.yml", []byte(render(t, d)))
	if err != nil {
		t.Fatalf("edited file no longer parses: %v", err)
	}
	if !proj.Services["app"].ReadOnly {
		t.Error("read_only was not set")
	}
}
