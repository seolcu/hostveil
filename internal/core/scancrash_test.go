package core

import (
	"context"
	"testing"

	"github.com/seolcu/hostveil/internal/check"
	"github.com/seolcu/hostveil/internal/diagnostics"
	"github.com/seolcu/hostveil/internal/history"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/platform"
)

// panickingChecker always panics from Check, standing in for the "a hand-
// written parser meets hostile or merely unusual host state" case
// check.runOne is built to survive.
type panickingChecker struct{ src model.Source }

func (c panickingChecker) Source() model.Source { return c.src }
func (c panickingChecker) Available(context.Context, platform.Env) (bool, string) {
	return true, ""
}
func (c panickingChecker) Check(context.Context, platform.Env) ([]model.Finding, error) {
	panic("a checker that crashed while reading the host")
}

// A checker's panic already degrades only its own domain (see
// check.runOne). What ScanWith adds is a diagnostics.CrashRecord, so
// `hostveil bugreport` has a trace for it afterward instead of nothing but
// the one-line "panic: ..." reason every UI already renders.
func TestAPanickingCheckerLeavesARecordForBugreport(t *testing.T) {
	dir := t.TempDir()
	e := New(Config{
		Registry: check.NewRegistry(panickingChecker{src: model.SourceSSH}),
		Store:    history.NewStore(dir),
		Version:  "v3-test",
	})

	report := e.Scan(context.Background(), nil)
	if len(report.Domains) != 1 || report.Domains[0].State != model.ScanError {
		t.Fatalf("got domains %+v, want one ScanError domain", report.Domains)
	}

	got, err := diagnostics.Crashes(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d crash records, want 1", len(got))
	}
	if got[0].Version != "v3-test" || got[0].Command != "scan" {
		t.Errorf("crash record does not carry the engine's identity: %+v", got[0])
	}
	if got[0].Where != "checker "+model.SourceSSH.String() {
		t.Errorf("crash record does not name the checker that crashed: %+v", got[0])
	}
}
