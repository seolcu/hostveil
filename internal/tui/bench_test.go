package tui

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func benchFindings(n int) []domain.Finding {
	out := make([]domain.Finding, n)
	sev := []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow}
	src := []domain.Source{domain.SourceTrivy, domain.SourceLynis, domain.SourceCompose}
	rem := []domain.RemediationKind{domain.RemediationAuto, domain.RemediationReview, domain.RemediationManual, domain.RemediationUnavailable}
	for i := 0; i < n; i++ {
		out[i] = domain.Finding{
			ID:          "trivy.cve-2024-" + itoa3(i),
			Title:       "Finding " + itoa3(i) + " in some long service name",
			Description: "A critical vulnerability was found in the service that affects all deployments running this version with extra detail to make the description longer.",
			HowToFix:    "Update the package to a patched version and restart the service.",
			Severity:    sev[i%len(sev)],
			Source:      src[i%len(src)],
			Service:     "service-" + itoa3(i%20),
			Remediation: rem[i%len(rem)],
		}
	}
	return out
}

func itoa3(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func newBenchModel(b *testing.B, n int) *model {
	live := domain.NewScanProgress(true)
	live.AddFindings(benchFindings(n))
	live.Finalize()
	m := NewApp(live, nil)
	m.width = 160
	m.height = 50
	m.phase = "ready"
	m.snapOK = true
	m.snap = live.Snapshot()
	m.rebuildTable()
	return m
}

func BenchmarkView_100(b *testing.B) {
	m := newBenchModel(b, 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View().Content
	}
}

func BenchmarkView_500(b *testing.B) {
	m := newBenchModel(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View().Content
	}
}

func BenchmarkView_2000(b *testing.B) {
	m := newBenchModel(b, 2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.View().Content
	}
}

func BenchmarkVisibleFindings_500(b *testing.B) {
	m := newBenchModel(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Invalidate to simulate calls across frames
		m.invalidateVisibleCache()
		m.visibleFindings()
	}
}

func BenchmarkVisibleFindingsCached_500(b *testing.B) {
	m := newBenchModel(b, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Within a single frame, second+ calls are cached
		m.visibleFindings()
		m.visibleFindings()
	}
}
