package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type PermissionsRule struct{}

func (r *PermissionsRule) Name() string { return "permissions" }

func (r *PermissionsRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	var findings []domain.Finding

	// Rule: privileged mode
	if svc.Privileged {
		findings = append(findings, domain.Finding{
			ID:       domain.FindingPermissionsPrivileged,
			Axis:     domain.AxisExcessivePermissions,
			Severity: domain.SeverityHigh,
			Scope:    domain.ScopeService,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Container runs in privileged mode",
			Description: name + " has privileged: true set. " +
				"This grants the container unrestricted access to the host kernel.",
			WhyRisky: "A compromised privileged container gives the attacker " +
				"full host root access, bypassing Docker's isolation.",
			HowToFix: "Remove privileged: true and add only the required capabilities:\n" +
				"  cap_add:\n    - NET_ADMIN\n    - SYS_TIME",
			Evidence:    map[string]string{"privileged": "true"},
			Remediation: domain.RemediationReview,
		})
	}

	// Rule: root user
	if strings.EqualFold(svc.User, "root") || svc.User == "" || svc.User == "0:0" {
		findings = append(findings, domain.Finding{
			ID:       domain.FindingPermissionsRootUser,
			Axis:     domain.AxisExcessivePermissions,
			Severity: domain.SeverityMedium,
			Scope:    domain.ScopeService,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Container runs as root",
			Description: name + " runs as the root user " +
				"(user: \"" + svc.User + "\").",
			WhyRisky: "Root inside the container is the same as root on the host " +
				"when volume mounts allow writes. A compromised root container " +
				"can escape via multiple kernel vectors.",
			HowToFix: "Set a non-root user:\n" +
				"  user: \"1000:1000\"",
			Evidence:    map[string]string{"user": svc.User},
			Remediation: domain.RemediationManual,
		})
	}

	// Rule: no-new-privileges disabled (implied by privileged or cap_add SYS_ADMIN)
	hasSysAdmin := false
	for _, cap := range svc.CapAdd {
		if strings.EqualFold(cap, "SYS_ADMIN") || strings.EqualFold(cap, "ALL") {
			hasSysAdmin = true
			break
		}
	}

	if hasSysAdmin {
		findings = append(findings, domain.Finding{
			ID:       domain.FindingPermissionsSysAdmin,
			Axis:     domain.AxisExcessivePermissions,
			Severity: domain.SeverityMedium,
			Scope:    domain.ScopeService,
			Source:   domain.SourceNativeCompose,
			Subject:  name,
			Service:  name,
			Title:    "Container has SYS_ADMIN capability",
			Description: name + " adds SYS_ADMIN (or ALL) capability, " +
				"which is often excessive.",
			WhyRisky: "SYS_ADMIN is a wide cap that permits mount, " +
				"namespace, and kernel operations. Most services don't need it.",
			HowToFix:    "Remove SYS_ADMIN from cap_add and add only specific capabilities needed.",
			Evidence:    map[string]string{"cap_add": strings.Join(svc.CapAdd, ", ")},
			Remediation: domain.RemediationManual,
		})
	}

	// Rule: sensitive host mounts
	for _, vol := range svc.Volumes {
		sensitive := isSensitiveMount(vol.Source)
		if sensitive {
			findings = append(findings, domain.Finding{
				ID:       domain.FindingPermissionsSensitiveMount,
				Axis:     domain.AxisExcessivePermissions,
				Severity: domain.SeverityHigh,
				Scope:    domain.ScopeService,
				Source:   domain.SourceNativeCompose,
				Subject:  name,
				Service:  name,
				Title:    "Sensitive host path mounted into container",
				Description: name + " mounts " + vol.Source +
					" from the host into the container at " + vol.Target + ".",
				WhyRisky: "Mounting sensitive paths like /etc/shadow or /var/run/docker.sock " +
					"gives the container access to host credentials or the Docker daemon.",
				HowToFix: "Remove the mount or use a Docker secret instead:\n" +
					"  secrets:\n    - my_secret",
				Evidence:    map[string]string{"mount": vol.Source + ":" + vol.Target},
				Remediation: domain.RemediationManual,
			})
		}
	}

	return findings
}

func isSensitiveMount(source string) bool {
	sensitive := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/ssh",
		"/root/.ssh",
		"/var/run/docker.sock",
		"/var/lib/docker",
		"/proc",
		"/sys",
	}
	for _, s := range sensitive {
		if source == s {
			return true
		}
	}
	return false
}
