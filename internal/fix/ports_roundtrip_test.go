package fix_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/check/checktest"
	portscheck "github.com/seolcu/hostveil/internal/check/ports"
	"github.com/seolcu/hostveil/internal/model"
)

// ports.redis-* both read and write the same redis.conf, the same shape as
// ssh's roundtrip. One fixture with none of the three directives set trips
// all three at once.
func portsRoundTripCases() []roundTrip {
	setup := func(t *testing.T, dir string) check.Checker {
		t.Helper()
		path := filepath.Join(dir, "redis.conf")
		writeFixture(t, path, "port 6379\n# no bind, no protected-mode, no renamed CONFIG\n")
		return &portscheck.Checker{RedisConfigPath: path}
	}
	ids := []string{"ports.redis-bind", "ports.redis-protected-mode", "ports.redis-disable-config"}
	out := make([]roundTrip, 0, len(ids))
	for _, id := range ids {
		out = append(out, roundTrip{want: id, setup: setup})
	}
	return out
}

// runPortsChecker mirrors runChecker, except it scripts a quiet `ss` first —
// ports.Check reads listening sockets unconditionally, and an unscripted `ss`
// would fail the whole check before the redis.conf directives under test are
// ever reached. No listeners means the generic-exposed-port and
// datastore/admin findings stay silent, so the redis directives are the only
// thing that can appear.
func runPortsChecker(t *testing.T, c check.Checker) map[string]model.Finding {
	t.Helper()
	env := checktest.New().Listeners("").Env()
	if ok, why := c.Available(context.Background(), env); !ok {
		t.Fatalf("the checker is unavailable: %s", why)
	}
	fs, err := c.Check(context.Background(), env)
	var pe *check.PartialError
	if err != nil && !errors.As(err, &pe) {
		t.Fatalf("the checker failed: %v", err)
	}
	out := map[string]model.Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

func TestEveryPortsFixActuallyClearsTheFindingItClaimsToFix(t *testing.T) {
	for _, tc := range portsRoundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			checker := tc.setup(t, t.TempDir())

			before := runPortsChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s on a host built to trip it; it found %v",
					tc.want, keysOf(before))
			}

			in, out := applyFirstAlternative(t, f)
			after := runPortsChecker(t, checker)
			if _, still := after[tc.want]; still {
				t.Errorf("%s survived its own fix.\n--- before ---\n%s\n--- after ---\n%s",
					tc.want, in, out)
			}
		})
	}
}

func TestAPortsFixClearsItsOwnFindingAndNoOther(t *testing.T) {
	for _, tc := range portsRoundTripCases() {
		t.Run(tc.want, func(t *testing.T) {
			checker := tc.setup(t, t.TempDir())

			before := runPortsChecker(t, checker)
			f, ok := before[tc.want]
			if !ok {
				t.Fatalf("the checker did not flag %s", tc.want)
			}
			applyFirstAlternative(t, f)
			after := runPortsChecker(t, checker)

			for id := range before {
				if id == tc.want {
					continue
				}
				if _, ok := after[id]; !ok {
					t.Errorf("fixing %s also cleared %s, which it does not claim to fix", tc.want, id)
				}
			}
			for id := range after {
				if _, ok := before[id]; ok {
					continue
				}
				t.Errorf("fixing %s introduced %s, which was not there before", tc.want, id)
			}
		})
	}
}
