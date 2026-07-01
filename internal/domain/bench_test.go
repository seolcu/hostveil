package domain

import (
	"testing"
)

func benchFindings(n int) []Finding {
	out := make([]Finding, n)
	sev := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
	src := []Source{SourceTrivy, SourceLynis, SourceCompose}
	rem := []RemediationKind{RemediationAuto, RemediationReview, RemediationManual, RemediationUnavailable}
	for i := 0; i < n; i++ {
		out[i] = Finding{
			ID:          "trivy.cve-2024-" + itoa4(i),
			Title:       "Finding with a fairly long title to simulate real data",
			Description: "Description of the finding that goes into some detail about what the issue is and how it manifests in production environments.",
			HowToFix:    "Update the package and restart the service to apply the fix.",
			Severity:    sev[i%len(sev)],
			Source:      src[i%len(src)],
			Service:     "service-" + itoa4(i%20),
			Remediation: rem[i%len(rem)],
			Evidence: map[string]string{
				"fixed_version": "1.2.3",
				"pkg_name":      "nginx",
			},
			Metadata: map[string]string{
				"compose_path": "/home/test/docker-compose.yml",
			},
		}
	}
	return out
}

func itoa4(n int) string {
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

func BenchmarkSnapshot_100(b *testing.B) {
	sp := NewScanProgress(true)
	sp.AddFindings(benchFindings(100))
	sp.Finalize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.Snapshot()
	}
}

func BenchmarkSnapshot_500(b *testing.B) {
	sp := NewScanProgress(true)
	sp.AddFindings(benchFindings(500))
	sp.Finalize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.Snapshot()
	}
}

func BenchmarkSnapshot_2000(b *testing.B) {
	sp := NewScanProgress(true)
	sp.AddFindings(benchFindings(2000))
	sp.Finalize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sp.Snapshot()
	}
}

func BenchmarkScoreFindings_2000(b *testing.B) {
	findings := benchFindings(2000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScoreFindings(findings)
	}
}

func BenchmarkRecalculate_2000(b *testing.B) {
	sp := NewScanProgress(true)
	sp.AddFindings(benchFindings(2000))
	sp.Finalize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sp.Recalculate()
	}
}
