package fix_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
	composecheck "github.com/seolcu/hostveil/internal/check/compose"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
)

// The compose round trip, on the layout internal/compose/discover.go calls
// "the ordinary case, not an exotic one": a base file and an override.
//
// The checker resolves the merge by asking docker, which is the whole point of
// effectiveProject — "a checker that re-implements somebody else's precedence
// rules is a checker that will disagree with reality on the hosts that
// matter." The fix layer does not. Parse labels the merged content with
// files[0], that path reaches the finding as Metadata["file"], and
// composeFilePath hands it to the builder. So the checker reads the project
// and the fix edits the first file of it.
//
// That is the AGENTS.md invariant in one sentence: "the file a fix creates is
// not necessarily the file that decides the outcome — and a fix that writes
// the wrong one still reports success, still records a checkpoint, and is
// contradicted at the next restart with nothing anywhere to explain it."

const composeBase = `services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
`

const composeOverride = `services:
  redis:
    ports:
      - "6379:6379"
`

// merged is what `docker compose -f base -f override config` prints: compose
// APPENDS port mappings rather than replacing them, so the same publication
// appears twice and the effective state is published on every interface.
const composeMerged = `services:
  redis:
    image: redis:7-alpine
    ports:
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
      - mode: ingress
        target: 6379
        published: "6379"
        protocol: tcp
`

// composeHost writes a base+override project and returns the checker that
// reads it, along with the two paths.
func composeHost(t *testing.T, dir string) (*composecheck.Checker, string, string) {
	t.Helper()
	base := filepath.Join(dir, "docker-compose.yml")
	override := filepath.Join(dir, "docker-compose.override.yml")
	for path, body := range map[string]string{base: composeBase, override: composeOverride} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return composecheck.New(), base, override
}

func composeRunner(base, override string) *checktest.Runner {
	return checktest.ComposeProjects(map[string]string{"stack": base + "," + override}).
		Script(composeMerged, "docker", "compose", "-f", base, "-f", override, "config")
}

// The fix must edit the file that decides the outcome, and on this project no
// single file does: both publish the port and compose appends them, so
// rewriting either one leaves the other still binding 0.0.0.0.
//
// Editing base and reporting success is the failure this pins. What hostveil
// should do instead is what persistSysctl does when the file it would write
// is outranked — decline, and say why — because a fix that cannot name the
// deciding file has not got one.
func TestTheComposeFixDoesNotEditAFileThatDoesNotDecide(t *testing.T) {
	dir := t.TempDir()
	checker, base, override := composeHost(t, dir)
	env := composeRunner(base, override).Env()

	fs, err := checker.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("the checker failed: %v", err)
	}
	var f model.Finding
	for _, c := range fs {
		if c.ID == "compose.ds018" {
			f = c
		}
	}
	if f.ID == "" {
		t.Fatalf("the checker did not report an exposed datastore on a project whose merge publishes 6379 on every interface; it found %v", idsOfFindings(fs))
	}

	fx, ok, err := fix.Default().Build(f)
	if err != nil {
		// Declining is the correct outcome — but it has to name both files
		// and say why, or the operator is left with a fix button that
		// vanished and no account of it.
		for _, want := range []string{base, override, "appends"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the fix declined without naming %q: %v", want, err)
			}
		}
		return
	}
	if !ok {
		t.Fatal("no fix is registered for compose.ds018")
	}

	a := fx.Actions[0]
	in, err := os.ReadFile(a.Path)
	if err != nil {
		t.Fatalf("reading %s: %v", a.Path, err)
	}
	out, err := a.Transform(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if err := os.WriteFile(a.Path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	// The merge is what decides, so the merge is what must change. Rewriting
	// one file while the other still publishes 6379 changes nothing docker
	// will do, and the operator has a checkpoint saying otherwise.
	other := override
	if a.Path == override {
		other = base
	}
	rest, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rest), `"6379:6379"`) {
		t.Errorf("the fix edited %s and reported success, but %s still publishes the port on every interface, "+
			"so the merged project docker actually runs is unchanged:\n--- edited ---\n%s\n--- untouched ---\n%s",
			filepath.Base(a.Path), filepath.Base(other), out, rest)
	}
}

func idsOfFindings(fs []model.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// The layout discover.go's comment is actually about: a base binding redis to
// loopback and an override republishing it. Exactly one file publishes the
// port on every interface, so exactly one file decides, and hostveil edits it.
//
// This is the case the old code got wrong in the quiet direction. It edited
// the base — where the binding is already 127.0.0.1 — so BindPortLoopback
// found nothing to rewrite, the builder returned "port not found on service",
// and Engine.classify demoted a fixable finding to Manual with no explanation
// anywhere. A capability lost to a resolution bug reads exactly like a
// capability that was never there.
func TestTheComposeFixEditsTheOverrideThatPublishesThePort(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "docker-compose.yml")
	override := filepath.Join(dir, "docker-compose.override.yml")
	if err := os.WriteFile(base, []byte(`services:
  redis:
    image: redis:7-alpine
    ports:
      - "127.0.0.1:6379:6379"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(override, []byte(composeOverride), 0o600); err != nil {
		t.Fatal(err)
	}

	checker := composecheck.New()
	env := composeRunner(base, override).Env()
	fs, err := checker.Check(context.Background(), env)
	if err != nil {
		t.Fatalf("the checker failed: %v", err)
	}
	var f model.Finding
	for _, c := range fs {
		if c.ID == "compose.ds018" {
			f = c
		}
	}
	if f.ID == "" {
		t.Fatalf("the checker did not report the exposure the merge produces; it found %v", idsOfFindings(fs))
	}

	fx, ok, err := fix.Default().Build(f)
	if err != nil || !ok {
		t.Fatalf("the fix declined the one layout it can resolve: %v (registered=%v)", err, ok)
	}
	if got := fx.Actions[0].Path; got != override {
		t.Errorf("the fix targets %s; the file that publishes the port on every interface is %s",
			filepath.Base(got), filepath.Base(override))
	}

	in, err := os.ReadFile(fx.Actions[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	out, err := fx.Actions[0].Transform(in)
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	if !strings.Contains(string(out), "127.0.0.1:6379:6379") {
		t.Errorf("the override still publishes on every interface after the fix:\n%s", out)
	}
}
