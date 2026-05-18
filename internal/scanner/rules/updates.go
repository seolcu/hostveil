package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type UpdatesRule struct{}

func (r *UpdatesRule) Name() string { return "updates" }

func (r *UpdatesRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	img := svc.Image

	// Rule: no version tag (uses :latest)
	if !strings.Contains(img, ":") {
		findings = append(findings, domain.Finding{
			ID:       "updates.latest_tag",
			Axis:     domain.AxisUpdateSupplyChain,
			Severity: domain.SeverityMedium,
			Scope:    domain.ScopeService,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Image uses the latest tag",
			Description: name + " uses image \"" + img +
				"\" without a specific version tag.",
			WhyRisky: "The :latest tag can change unexpectedly between deployments, " +
				"introducing breaking changes or security regressions without notice.",
			HowToFix: "Pin to a specific version:\n" +
				"  image: " + img + ":<version>",
			Evidence:    map[string]string{"image": img},
			Remediation: domain.RemediationAuto,
		})
	}

	return findings
}
