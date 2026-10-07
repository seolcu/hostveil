package ports

import (
	"context"
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

const postgresListening = `LISTEN 0 244 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=812,fd=6))
LISTEN 0 244 [::]:5432 [::]:* users:(("postgres",pid=812,fd=7))`

func withUFW(status string) platform.Env {
	r := checktest.New().Listeners(postgresListening).
		Script(status, "ufw", "status", "verbose").
		Script(status, "ufw", "status")
	return r.Env()
}

const ufwAllowSSH = `Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`

// The loop for the ufw fix: the checker flags Postgres with ufw running and
// letting it through, the fix prepends a deny, and the checker — reading ufw
// the way ufw applies its rules — no longer reports the port reachable.
func TestTheUFWDenyClosesTheDatastoreFinding(t *testing.T) {
	fs, err := New().Check(context.Background(), withUFW(ufwAllowSSH))
	if err != nil {
		t.Fatal(err)
	}
	f, ok := findByID(fs, "ports.exposed-datastore")
	if !ok {
		t.Fatalf("not flagged: %v", fs)
	}
	if f.Remediation != model.RemediationReview {
		t.Fatalf("remediation = %v", f.Remediation)
	}
	fx, ok, err := fix.Default().Build(f)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if got := fx.Actions[0].Commands[0]; !slices.Equal(got, []string{"ufw", "prepend", "deny", "5432/tcp"}) {
		t.Errorf("runs %v", got)
	}

	after := `Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
5432/tcp                   DENY IN     Anywhere
22/tcp                     ALLOW IN    Anywhere
5432/tcp (v6)              DENY IN     Anywhere (v6)
22/tcp (v6)                ALLOW IN    Anywhere (v6)
`
	fs, err = New().Check(context.Background(), withUFW(after))
	if err != nil {
		t.Fatal(err)
	}
	if _, still := findByID(fs, "ports.exposed-datastore"); still {
		t.Error("a port ufw refuses in both families is still reported reachable")
	}
}

func TestWithoutUFWTheFindingSaysWhy(t *testing.T) {
	fs, err := New().Check(context.Background(), platform.Env{Runner: noFirewall(postgresListening)})
	if err != nil {
		t.Fatal(err)
	}
	f, _ := findByID(fs, "ports.exposed-datastore")
	if f.Remediation != model.RemediationManual || f.WhyNoFix == "" {
		t.Errorf("remediation %v why %q", f.Remediation, f.WhyNoFix)
	}
}
