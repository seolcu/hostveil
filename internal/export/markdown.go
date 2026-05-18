package export

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

func title(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func Markdown(r *domain.ScanResult) string {
	var b strings.Builder

	b.WriteString("# Hostveil Security Report\n\n")

	b.WriteString(fmt.Sprintf("**Overall Score**: %d (%s)\n\n", r.ScoreReport.Overall, r.ScoreReport.Grade()))

	b.WriteString("## Axis Scores\n\n")
	for _, axis := range domain.AllAxes() {
		score := r.ScoreReport.AxisScores[axis]
		b.WriteString(fmt.Sprintf("- **%s**: %d\n", axis.Label(), score))
	}

	b.WriteString("\n## Severity Breakdown\n\n")
	for _, sev := range []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow} {
		count := r.FindingsBySeverity(sev)
		if count > 0 {
			b.WriteString(fmt.Sprintf("- **%s**: %d\n", title(sev.String()), count))
		}
	}

	b.WriteString(fmt.Sprintf("\n## Findings (%d total)\n\n", r.TotalFindings()))
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("### [%s] %s\n", strings.ToUpper(f.Severity.String()), f.Title))
		b.WriteString(fmt.Sprintf("- **ID**: %s\n", f.ID))
		b.WriteString(fmt.Sprintf("- **Axis**: %s\n", f.Axis.Label()))
		b.WriteString(fmt.Sprintf("- **Scope**: %s\n", f.Scope.String()))
		b.WriteString(fmt.Sprintf("- **Service**: %s\n", f.Service))
		b.WriteString(fmt.Sprintf("- **Remediation**: %s\n", f.Remediation.Label()))
		b.WriteString(fmt.Sprintf("\n%s\n\n", f.Description))
		b.WriteString(fmt.Sprintf("**Why it's risky**: %s\n\n", f.WhyRisky))
		b.WriteString(fmt.Sprintf("**How to fix**: %s\n\n", f.HowToFix))
		if len(f.Evidence) > 0 {
			b.WriteString("**Evidence**:\n")
			for k, v := range f.Evidence {
				b.WriteString(fmt.Sprintf("- %s: `%s`\n", k, v))
			}
			b.WriteString("\n")
		}
		b.WriteString("---\n\n")
	}

	return b.String()
}
