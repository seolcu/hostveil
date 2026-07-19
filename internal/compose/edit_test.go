package compose

import (
	"strings"
	"testing"
)

func loadOrFail(t *testing.T, yaml string) *Doc {
	t.Helper()
	d, err := Load([]byte(yaml))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return d
}

func TestAddSecurityOpt(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: myapp\n")
	if err := d.AddSecurityOpt("app", "no-new-privileges:true"); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Bytes()
	if !strings.Contains(string(out), "no-new-privileges:true") {
		t.Errorf("security_opt not added:\n%s", out)
	}
	// Idempotent: applying again does not duplicate.
	_ = d.AddSecurityOpt("app", "no-new-privileges:true")
	out2, _ := d.Bytes()
	if strings.Count(string(out2), "no-new-privileges") != 1 {
		t.Errorf("security_opt duplicated:\n%s", out2)
	}
}

func TestSetScalarRestart(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: myapp\n")
	if err := d.SetScalar("app", "restart", "unless-stopped"); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Bytes()
	if !strings.Contains(string(out), "restart: unless-stopped") {
		t.Errorf("restart not set:\n%s", out)
	}
}

func TestBindPortLoopback(t *testing.T) {
	d := loadOrFail(t, "services:\n  cache:\n    image: redis\n    ports:\n      - \"6379:6379\"\n")
	if err := d.BindPortLoopback("cache", "6379"); err != nil {
		t.Fatal(err)
	}
	out, _ := d.Bytes()
	if !strings.Contains(string(out), "127.0.0.1:6379:6379") {
		t.Errorf("port not rebound to loopback:\n%s", out)
	}
	// The edited file must still parse and no longer be exposed.
	proj, err := Parse("x.yml", out)
	if err != nil {
		t.Fatalf("edited file no longer parses: %v", err)
	}
	for _, p := range proj.Services["cache"].Ports {
		if p.ExposedOnAllInterfaces() {
			t.Error("port still exposed after loopback bind")
		}
	}
}

func TestEditMissingServiceErrors(t *testing.T) {
	d := loadOrFail(t, "services:\n  app:\n    image: myapp\n")
	if err := d.SetScalar("nope", "restart", "always"); err == nil {
		t.Error("expected error for missing service")
	}
}

// FuzzEdit ensures the AST editors never panic and always render parseable
// YAML, even on odd-but-valid compose inputs.
func FuzzEdit(f *testing.F) {
	f.Add("services:\n  a:\n    image: x\n    ports:\n      - \"80:80\"\n")
	f.Add("services:\n  a:\n    image: x\n    security_opt:\n      - seccomp:unconfined\n")
	f.Fuzz(func(t *testing.T, yaml string) {
		d, err := Load([]byte(yaml))
		if err != nil {
			return
		}
		if len(d.root.Content) == 0 {
			return
		}
		_ = d.AddSecurityOpt("a", "no-new-privileges:true")
		_ = d.SetScalar("a", "restart", "unless-stopped")
		_ = d.BindPortLoopback("a", "80")
		out, err := d.Bytes()
		if err != nil {
			return
		}
		// The editor's invariant: whatever it renders must round-trip back
		// through the editor (valid YAML mapping), so a later fix never
		// reads a corrupted document.
		if _, err := Load(out); err != nil {
			t.Fatalf("edit produced un-reloadable YAML: %v\ninput:\n%s\noutput:\n%s", err, yaml, out)
		}
	})
}

// TestMinimalDiffPreservesUnchangedLines guards issue #521: a single-field fix
// must change only the affected line, leaving aligned inline comments and
// blank lines between services untouched (no whole-file reflow).
func TestMinimalDiffPreservesUnchangedLines(t *testing.T) {
	src := `# A media server stack.
services:
  jellyfin:
    image: jellyfin/jellyfin:10.8.0   # intentionally old
    ports:
      - "8096:8096"                    # published on 0.0.0.0

  redis:
    image: redis:6.0                   # intentionally old
    ports:
      - "6379:6379"                    # datastore on 0.0.0.0
`
	want := `# A media server stack.
services:
  jellyfin:
    image: jellyfin/jellyfin:10.8.0   # intentionally old
    ports:
      - "8096:8096"                    # published on 0.0.0.0

  redis:
    image: redis:6.0                   # intentionally old
    ports:
      - "127.0.0.1:6379:6379"                    # datastore on 0.0.0.0
`
	d := loadOrFail(t, src)
	if err := d.BindPortLoopback("redis", "6379"); err != nil {
		t.Fatal(err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != want {
		t.Errorf("minimal diff not preserved.\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// TestMinimalDiffFallsBackWhenAmbiguous ensures rendering still produces valid,
// intended YAML even when the source layout defeats the minimal path (here a
// flow sequence), by falling back to the full re-encode.
func TestMinimalDiffFallbackStillCorrect(t *testing.T) {
	d := loadOrFail(t, "services:\n  cache:\n    image: redis\n    ports: [\"6379:6379\"]\n")
	if err := d.BindPortLoopback("cache", "6379"); err != nil {
		t.Fatal(err)
	}
	out, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "127.0.0.1:6379:6379") {
		t.Errorf("fallback did not apply the bind:\n%s", out)
	}
	proj, err := Parse("x.yml", out)
	if err != nil {
		t.Fatalf("fallback produced unparseable YAML: %v", err)
	}
	for _, p := range proj.Services["cache"].Ports {
		if p.ExposedOnAllInterfaces() {
			t.Error("port still exposed after fallback bind")
		}
	}
}
