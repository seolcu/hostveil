package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type RuntimeRule struct{}

func (r *RuntimeRule) Name() string { return "runtime" }

func (r *RuntimeRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	// Rule: no-new-privileges disabled (no security_opt, privileged mode)
	if !svc.Privileged && svc.CapDrop == nil {
		hasNoNewPriv := false
		for _, cap := range svc.CapDrop {
			if strings.EqualFold(cap, "ALL") {
				hasNoNewPriv = true
				break
			}
		}
		if !hasNoNewPriv {
			findings = append(findings, domain.Finding{
				ID:          domain.FindingRuntimeNoNewPrivileges,
				Axis:        domain.AxisExcessivePermissions,
				Severity:    domain.SeverityLow,
				Scope:       domain.ScopeService,
				Source:      domain.SourceNativeCompose,
				Subject:     name,
				Service:     name,
				Title:       "Container allows privilege escalation",
				Description: name + " does not drop all capabilities or set no-new-privileges.",
				WhyRisky: "Without dropping unnecessary capabilities, a compromised container " +
					"can escalate privileges via setuid binaries or kernel exploits.",
				HowToFix: "Drop all capabilities and add only what's needed:\n" +
					"  cap_drop:\n    - ALL\n  cap_add:\n    - NET_BIND_SERVICE",
				Evidence:    map[string]string{"privileged": "false"},
				Remediation: domain.RemediationAuto,
			})
		}
	}

	// Rule: read-only root filesystem not set
	if !svc.ReadOnly {
		hasWritableRoot := false
		for _, vol := range svc.Volumes {
			if vol.Target == "/" || vol.Target == "/data" {
				hasWritableRoot = true
			}
		}
		if !hasWritableRoot {
			findings = append(findings, domain.Finding{
				ID:          domain.FindingRuntimeWritableRootfs,
				Axis:        domain.AxisExcessivePermissions,
				Severity:    domain.SeverityLow,
				Scope:       domain.ScopeService,
				Source:      domain.SourceNativeCompose,
				Subject:     name,
				Service:     name,
				Title:       "Container root filesystem is writable",
				Description: name + " does not set read_only: true.",
				WhyRisky: "A writable root filesystem lets compromised containers " +
					"modify binaries, write to /tmp, and persist changes.",
				HowToFix: "Set read_only: true and mount specific writable directories:\n" +
					"  read_only: true\n  tmpfs:\n    - /tmp",
				Evidence:    map[string]string{"read_only": "false"},
				Remediation: domain.RemediationAuto,
			})
		}
	}

	return findings
}
