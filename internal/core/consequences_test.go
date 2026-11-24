package core

import (
	"slices"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func ev(id string, sev model.Severity, src model.Source, rem model.RemediationKind, svc string, kv ...string) model.Finding {
	opts := []model.FindingOption{}
	if svc != "" {
		opts = append(opts, model.WithService(svc))
	}
	for i := 0; i+1 < len(kv); i += 2 {
		opts = append(opts, model.WithEvidence(kv[i], kv[i+1]))
	}
	return model.NewFinding(id, "t", sev, src, rem, opts...)
}

// One published port is reported by three domains; the compose fix removes
// all three, and a native service on another port is left alone.
func TestConsequencesLinkToTheComposeFixThatClosesThem(t *testing.T) {
	db := ev("compose.ds018", model.SeverityHigh, model.SourceCompose, model.RemediationAuto, "db", "port", "5432")
	fs := []model.Finding{
		db,
		ev("ports.exposed-datastore", model.SeverityHigh, model.SourcePorts, model.RemediationManual, "docker-proxy:5432", "process", "docker-proxy", "port", "5432"),
		ev("ports.exposed-datastore", model.SeverityHigh, model.SourcePorts, model.RemediationManual, "redis-server:6379", "process", "redis-server", "port", "6379"),
		ev("firewall.docker-bypass", model.SeverityHigh, model.SourceFirewall, model.RemediationReview, "", "published", "5432 (cloud-db-1)"),
		ev("ports.exposed", model.SeverityLow, model.SourcePorts, model.RemediationManual, "", "ports", "5432 (docker-proxy), 2375 (dockerd)"),
	}
	linkConsequences(fs)
	want := []string{db.Key()}
	if !slices.Equal(fs[1].ResolvedBy, want) || !slices.Equal(fs[3].ResolvedBy, want) {
		t.Errorf("docker-proxy and bypass findings link to the compose fix: %v / %v", fs[1].ResolvedBy, fs[3].ResolvedBy)
	}
	if fs[2].ResolvedBy != nil {
		t.Error("a native Redis is not closed by a compose file")
	}
	if fs[4].ResolvedBy != nil {
		t.Error("ports.exposed also lists dockerd's 2375, which the compose fix does not close")
	}

	b := model.ScoreReport(fs, nil)
	without := model.ScoreReport(append([]model.Finding{db}, fs[2], fs[4]), nil)
	if b.AfterSafeFixes != without.AfterSafeFixes {
		t.Errorf("the projection counts the linked findings as gone: %d, want %d", b.AfterSafeFixes, without.AfterSafeFixes)
	}
}
