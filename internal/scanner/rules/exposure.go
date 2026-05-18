package rules

import (
	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type ExposureRule struct{}

func (r *ExposureRule) Name() string { return "exposure" }

func (r *ExposureRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	for _, p := range svc.Ports {
		// Rule: public port binding (not bound to 127.0.0.1)
		if p.HostIP == "" || p.HostIP == "0.0.0.0" {
			sev := domain.SeverityMedium
			rem := domain.RemediationReview
			if p.HostIP == "0.0.0.0" {
				rem = domain.RemediationAuto
			}

			findings = append(findings, domain.Finding{
				ID:       "exposure.public_binding",
				Axis:     domain.AxisUnnecessaryExposure,
				Severity: sev,
				Scope:    domain.ScopeService,
				Source:   domain.SourceNativeCompose,
				Subject:  name,
				Service:  name,
				Title:    "Service is published on a public interface",
				Description: name + " publishes " + formatPort(p) +
					" on a publicly reachable host interface.",
				WhyRisky: "Public bindings increase the attack surface. " +
					"Services should bind to localhost when a reverse proxy handles external traffic.",
				HowToFix: "Bind the port to 127.0.0.1:\n" +
					"  ports:\n    - \"127.0.0.1:" + fmtPort(p) + "\"",
				Evidence:    map[string]string{"port": formatPort(p)},
				Remediation: rem,
			})
		}

		// Rule: reverse proxy expected (port 80 or 443 exposed)
		if p.Target == 80 || p.Target == 443 {
			findings = append(findings, domain.Finding{
				ID:       "exposure.reverse_proxy_expected",
				Axis:     domain.AxisUnnecessaryExposure,
				Severity: domain.SeverityHigh,
				Scope:    domain.ScopeService,
				Source:   domain.SourceNativeCompose,
				Subject:  name,
				Service:  name,
				Title:    "Service should sit behind a reverse proxy",
				Description: name + " is directly published on " +
					formatPort(p) + " even though it is usually safer behind a reverse proxy.",
				WhyRisky: "Directly publishing user-facing apps makes TLS, " +
					"auth hardening, and access control easier to miss.",
				HowToFix: "Route the service through a reverse proxy " +
					"and remove the direct public port where possible.",
				Evidence:    map[string]string{"port": formatPort(p)},
				Remediation: domain.RemediationReview,
			})
		}
	}

	return findings
}

func formatPort(p compose.Port) string {
	s := itoa(p.Target)
	if p.Published > 0 {
		s = itoa(p.Published) + ":" + itoa(p.Target)
	}
	if p.Protocol != "tcp" {
		s += "/" + p.Protocol
	}
	return s
}

func fmtPort(p compose.Port) string {
	return itoa(p.Published) + ":" + itoa(p.Target)
}

func itoa(n uint16) string {
	if n == 0 {
		return ""
	}
	digits := []byte("0123456789")
	var buf [5]byte
	i := len(buf)
	for n >= 10 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	i--
	buf[i] = digits[n]
	return string(buf[i:])
}
