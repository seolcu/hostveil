package compose

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// configRunner answers `docker compose ... config` with merged and
// `... config --no-interpolate` with raw (or an error when raw is "").
type configRunner struct{ merged, raw string }

func (c configRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	if slices.Contains(args, "--no-interpolate") {
		if c.raw == "" {
			return nil, errors.New("unknown flag: --no-interpolate")
		}
		return []byte(c.raw), nil
	}
	return []byte(c.merged), nil
}

func (configRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

const mergedConfig = `services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: s3cretvalue123456
      API_TOKEN: abcdef0123456789
`

const rawConfig = `services:
  db:
    image: postgres:17
    env_file:
      - path: /srv/db/db.env
        required: true
    environment:
      POSTGRES_PASSWORD: ${PGPASS}
`

// The merged config substitutes ${VAR} and inlines env_file; the raw one
// keeps the environment and env_file as written.
func TestEffectiveProjectKeepsTheEnvironmentAsWritten(t *testing.T) {
	p, err := effectiveProject(context.Background(), configRunner{mergedConfig, rawConfig}, []string{"/srv/db/docker-compose.yml"})
	if err != nil {
		t.Fatal(err)
	}
	db := p.Services["db"]
	if db.Environment["POSTGRES_PASSWORD"] != "s3cretvalue123456" {
		t.Errorf("the merged environment is what runs, got %v", db.Environment)
	}
	if db.RawEnvironment["POSTGRES_PASSWORD"] != "${PGPASS}" {
		t.Errorf("the raw environment is what the file says, got %v", db.RawEnvironment)
	}
	if _, inlined := db.RawEnvironment["API_TOKEN"]; inlined {
		t.Error("a variable from env_file is not in the compose file's environment")
	}
	if !slices.Equal(db.EnvFile, []string{"/srv/db/db.env"}) {
		t.Errorf("env_file long form, got %v", db.EnvFile)
	}
}

// A compose that does not know --no-interpolate leaves the project as the
// merged config describes it.
func TestEffectiveProjectWithoutNoInterpolate(t *testing.T) {
	p, err := effectiveProject(context.Background(), configRunner{mergedConfig, ""}, []string{"/srv/db/docker-compose.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Services["db"].RawEnvironment != nil {
		t.Error("no raw environment was read")
	}
}

func TestEnvFileShortAndLongForms(t *testing.T) {
	for _, yml := range []string{
		"services:\n  a:\n    env_file: one.env\n",
		"services:\n  a:\n    env_file: [one.env]\n",
		"services:\n  a:\n    env_file:\n      - path: one.env\n        required: false\n",
	} {
		p, err := Parse("x", []byte(yml))
		if err != nil {
			t.Fatalf("%q: %v", yml, err)
		}
		if got := p.Services["a"].EnvFile; len(got) != 1 || !strings.HasSuffix(got[0], "one.env") {
			t.Errorf("%q: env_file = %v", yml, got)
		}
	}
}
