package compose

import (
	"strings"
	"testing"
)

// Compose lets you say the same thing several ways, and the custom
// unmarshallers in project.go exist for exactly that. Both of them were at 0%.
//
// A break here is silent in the worst direction. Every rule in
// internal/check/compose reads the normalised value, so an environment form
// that came back empty would not produce an error or a Degraded domain — it
// would produce a service with no environment, and a compose file full of
// hardcoded passwords would audit clean. The fixtures happen to use the map
// form, so the list form — the other half of what people write — was never
// executed by a test at all.

func serviceFrom(t *testing.T, body string) Service {
	t.Helper()
	p, err := Parse("docker-compose.yml", []byte("services:\n  app:\n    image: x\n"+body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s, ok := p.Services["app"]
	if !ok {
		t.Fatal("the service did not parse at all")
	}
	return s
}

func TestEnvironmentAcceptsBothComposeForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want map[string]string
	}{
		{
			name: "map form",
			body: "    environment:\n      POSTGRES_PASSWORD: hunter2\n      POSTGRES_USER: app\n",
			want: map[string]string{"POSTGRES_PASSWORD": "hunter2", "POSTGRES_USER": "app"},
		},
		{
			name: "list form",
			body: "    environment:\n      - POSTGRES_PASSWORD=hunter2\n      - POSTGRES_USER=app\n",
			want: map[string]string{"POSTGRES_PASSWORD": "hunter2", "POSTGRES_USER": "app"},
		},
		{
			// `- NAME` with no value passes the variable through from the
			// host's environment. The value is genuinely unknown here, and it
			// must come back empty rather than as the name: a secret rule
			// that saw POSTGRES_PASSWORD=POSTGRES_PASSWORD would report a
			// hardcoded secret on a compose file that hardcodes nothing.
			name: "list form, pass-through with no value",
			body: "    environment:\n      - POSTGRES_PASSWORD\n",
			want: map[string]string{"POSTGRES_PASSWORD": ""},
		},
		{
			// Only the first = separates. Base64 and connection strings are
			// full of them, and splitting on the last one would truncate the
			// value; splitting on all of them would drop it.
			name: "list form, value containing =",
			body: "    environment:\n      - DATABASE_URL=postgres://u:p@h/db?sslmode=require\n",
			want: map[string]string{"DATABASE_URL": "postgres://u:p@h/db?sslmode=require"},
		},
		{
			// YAML types the unquoted scalars; the audit wants strings. An
			// int that came back as "" would make a port or a flag invisible.
			name: "map form with non-string scalars",
			body: "    environment:\n      PORT: 3306\n      DEBUG: true\n      EMPTY:\n",
			want: map[string]string{"PORT": "3306", "DEBUG": "true", "EMPTY": ""},
		},
		{
			name: "absent",
			body: "",
			want: map[string]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceFrom(t, tc.body).Environment
			if len(got) != len(tc.want) {
				t.Fatalf("environment = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("environment[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestEnvFileAcceptsAScalarOrAList(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"scalar", "    env_file: .env\n", []string{".env"}},
		{"list", "    env_file:\n      - .env\n      - .env.prod\n", []string{".env", ".env.prod"}},
		{"inline list", "    env_file: [.env, .env.prod]\n", []string{".env", ".env.prod"}},
		{"absent", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := serviceFrom(t, tc.body).EnvFile
			if len(got) != len(tc.want) {
				t.Fatalf("env_file = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("env_file[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The forms have to reach the rules, not just the struct. This is the same
// compose file written both ways, and the audit must not read them
// differently — the list form was the one no test had ever run.
func TestTheSameServiceWrittenBothWaysAuditsTheSame(t *testing.T) {
	mapForm := serviceFrom(t, "    environment:\n      POSTGRES_PASSWORD: hunter2secret\n")
	listForm := serviceFrom(t, "    environment:\n      - POSTGRES_PASSWORD=hunter2secret\n")
	if mapForm.Environment["POSTGRES_PASSWORD"] != listForm.Environment["POSTGRES_PASSWORD"] {
		t.Errorf("the two compose forms of one variable parsed differently: %q vs %q",
			mapForm.Environment["POSTGRES_PASSWORD"], listForm.Environment["POSTGRES_PASSWORD"])
	}
	if !strings.Contains(mapForm.Environment["POSTGRES_PASSWORD"], "hunter2") {
		t.Fatal("neither form carried the value, so this test compares two empty maps")
	}
}
