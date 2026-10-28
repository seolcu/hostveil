package fix

import (
	"strings"
	"testing"

	forensiccheck "github.com/seolcu/hostveil/internal/check/forensic"
	"github.com/seolcu/hostveil/internal/model"
)

func forensicFinding(id string, meta map[string]string) model.Finding {
	opts := []model.FindingOption{model.WithService("www-data")}
	for k, v := range meta {
		opts = append(opts, model.WithMetadata(k, v))
	}
	return model.NewFinding(id, "t", model.SeverityLow, model.SourceForensic, model.RemediationReview, opts...)
}

func TestJournaldFixesWriteOneDropInAndRestart(t *testing.T) {
	meta := map[string]string{"journald_dropin": forensiccheck.JournaldDropInDir + "90-hostveil-forensic.conf"}
	var content []byte
	for _, id := range []string{"forensic.journald-volatile", "forensic.journald-retention"} {
		fx, ok, err := Default().Build(forensicFinding(id, meta))
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", id, ok, err)
		}
		a := fx.Actions[0]
		if fx.EffectiveKind() != model.RemediationReview || !a.CreateIfMissing || len(a.AfterWrite) == 0 {
			t.Errorf("%s: kind %v, create %v, afterwrite %v", id, fx.EffectiveKind(), a.CreateIfMissing, a.AfterWrite)
		}
		if content, err = a.Transform(content); err != nil {
			t.Fatal(err)
		}
	}
	want := "[Journal]\nStorage=persistent\nMaxRetentionSec=90day\n"
	if string(content) != want {
		t.Errorf("drop-in after both fixes:\n%s\nwant:\n%s", content, want)
	}
	// Idempotent: applying again changes nothing.
	fx, _, _ := Default().Build(forensicFinding("forensic.journald-volatile", meta))
	again, _ := fx.Actions[0].Transform(content)
	if string(again) != want {
		t.Errorf("re-applying changed the file:\n%s", again)
	}
}

func TestJournaldFixRefusesWithoutAWinningDropIn(t *testing.T) {
	if _, _, err := Default().Build(forensicFinding("forensic.journald-volatile", nil)); err == nil {
		t.Error("built a fix with no drop-in path")
	}
}

func TestServiceExecAuditRuleIsTheOneTheCheckerLooksFor(t *testing.T) {
	fx, ok, err := Default().Build(forensicFinding("forensic.service-exec-unaudited", map[string]string{"service_uid": "33"}))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	a := fx.Actions[0]
	if a.Path != forensiccheck.AuditRulesPath {
		t.Errorf("writes %s, the checker names %s", a.Path, forensiccheck.AuditRulesPath)
	}
	out, err := a.Transform(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "-S execve -F euid=33 -k "+forensiccheck.AuditKey) {
		t.Errorf("rule file:\n%s", out)
	}
	twice, _ := a.Transform(out)
	if string(twice) != string(out) {
		t.Error("re-applying duplicated the rule")
	}
	if _, _, err := Default().Build(forensicFinding("forensic.service-exec-unaudited", map[string]string{"service_uid": "x; rm"})); err == nil {
		t.Error("accepted a non-numeric uid")
	}
}

func TestLogrotateFixReachesTheTargetTheCheckerUses(t *testing.T) {
	src := "/var/log/syslog\n/var/log/auth.log\n{\n\trotate 4\n\tweekly\n\tpostrotate\n\t\trotate 1\n\tendscript\n}\n" +
		"/var/log/kern.log {\n\tdaily\n}\n" +
		"/var/log/big.log {\n\tsize 100M\n\trotate 2\n}\n"
	fx, ok, err := Default().Build(forensicFinding("forensic.logrotate-short",
		map[string]string{"logrotate_file": "/etc/logrotate.d/rsyslog", "default_period": "weekly"}))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	out, err := fx.Actions[0].Transform([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range forensiccheck.ParseLogrotate(string(out)) {
		if d := b.Days(0, "weekly"); d >= 0 && d < 90 {
			t.Errorf("block %v still keeps %d days:\n%s", b.Paths, d, out)
		}
	}
	if !strings.Contains(string(out), "\t\trotate 1\n") {
		t.Error("rewrote a line inside a postrotate script")
	}
	if !strings.Contains(string(out), "size 100M\n\trotate 2") {
		t.Error("touched a size-only block, whose coverage depends on traffic")
	}
	same, _ := fx.Actions[0].Transform(out)
	if string(same) != string(out) {
		t.Error("not idempotent")
	}
}
