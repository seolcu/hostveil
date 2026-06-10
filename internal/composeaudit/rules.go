package composeaudit

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func auditProject(f *compose.File, project Project) []domain.Finding {
	svcs, err := f.ServiceNames()
	if err != nil || len(svcs) == 0 {
		return nil
	}

	var all []domain.Finding
	for _, svc := range svcs {
		all = append(all, checkPrivileged(f, svc, project)...)
		all = append(all, checkReadOnly(f, svc, project)...)
		all = append(all, checkPIDMode(f, svc, project)...)
		all = append(all, checkIPCMode(f, svc, project)...)
		all = append(all, checkCapAdd(f, svc, project)...)
		all = append(all, checkNoNewPrivileges(f, svc, project)...)
		all = append(all, checkUserNS(f, svc, project)...)
		all = append(all, checkRestart(f, svc, project)...)
		all = append(all, checkUser(f, svc, project)...)
		all = append(all, checkMemoryLimit(f, svc, project)...)
		all = append(all, checkCPULimit(f, svc, project)...)
		all = append(all, checkHealthcheck(f, svc, project)...)
		all = append(all, checkTmpfs(f, svc, project)...)
		all = append(all, checkSeccomp(f, svc, project)...)
		all = append(all, checkAppArmor(f, svc, project)...)
		all = append(all, checkNetworkMode(f, svc, project)...)
		all = append(all, checkPortBinding(f, svc, project)...)
		all = append(all, checkVolumeRO(f, svc, project)...)
	}
	return all
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func composeMeta(project Project, svc string) map[string]string {
	return map[string]string{
		"compose_path": project.ComposePath,
		"project":      project.Name,
		"service":      svc,
	}
}

func checkPrivileged(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "privileged")
	if v == "true" {
		return []domain.Finding{{
			ID:          "compose.ds001",
			Title:       "Container runs in privileged mode",
			Description: fmt.Sprintf("Service %q has privileged: true, granting all capabilities.", svc),
			HowToFix:    "Remove privileged: true and add only required capabilities via cap_add.",
			Severity:    domain.SeverityHigh,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkReadOnly(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "read_only")
	if v != "true" {
		return []domain.Finding{{
			ID:          "compose.ds002",
			Title:       "Container root filesystem is writable",
			Description: fmt.Sprintf("Service %q has read_only disabled or unset.", svc),
			HowToFix:    "Set read_only: true and mount writable paths as tmpfs or volumes.",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkPIDMode(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "pid")
	if v == "host" {
		return []domain.Finding{{
			ID:          "compose.ds003",
			Title:       "Container shares host PID namespace",
			Description: fmt.Sprintf("Service %q has pid: host, exposing host processes.", svc),
			HowToFix:    "Remove pid: host. Use a sidecar if process visibility is needed.",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkIPCMode(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "ipc")
	if v == "host" {
		return []domain.Finding{{
			ID:          "compose.ds004",
			Title:       "Container shares host IPC namespace",
			Description: fmt.Sprintf("Service %q has ipc: host, exposing host IPC.", svc),
			HowToFix:    "Remove ipc: host to isolate container IPC.",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

var dangerousCaps = []string{"SYS_ADMIN", "NET_ADMIN", "SYS_RAWIO", "SYS_PTRACE", "SYS_MODULE"}

func checkCapAdd(f *compose.File, svc string, project Project) []domain.Finding {
	adds, err := f.GetFieldStrings(svc, "cap_add")
	if err != nil || len(adds) == 0 {
		return nil
	}
	var found []string
	for _, cap := range dangerousCaps {
		for _, a := range adds {
			if strings.EqualFold(a, cap) {
				found = append(found, cap)
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	return []domain.Finding{{
		ID:          "compose.ds005",
		Title:       "Container adds dangerous capabilities",
		Description: fmt.Sprintf("Service %q adds %s to its capabilities.", svc, strings.Join(found, ", ")),
		HowToFix:    fmt.Sprintf("Remove %s from cap_add. Drop all with cap_drop: ALL and add only needed capabilities.", strings.Join(found, ", ")),
		Severity:    domain.SeverityHigh,
		Source:      domain.SourceCompose,
		Service:     svc,
		Remediation: domain.RemediationUnavailable,
		Metadata:    composeMeta(project, svc),
	}}
}

func checkNoNewPrivileges(f *compose.File, svc string, project Project) []domain.Finding {
	opts, err := f.GetFieldStrings(svc, "security_opt")
	if err != nil {
		return nil
	}
	for _, o := range opts {
		if strings.Contains(o, "no-new-privileges") {
			return nil
		}
	}
	return []domain.Finding{{
		ID:          "compose.ds006",
		Title:       "no-new-privileges is missing",
		Description: fmt.Sprintf("Service %q does not set no-new-privileges in security_opt.", svc),
		HowToFix:    `Add security_opt: ["no-new-privileges:true"] to prevent privilege escalation.`,
		Severity:    domain.SeverityMedium,
		Source:      domain.SourceCompose,
		Service:     svc,
		Remediation: domain.RemediationUnavailable,
		Metadata:    composeMeta(project, svc),
	}}
}

func checkUserNS(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "userns_mode")
	if v == "host" {
		return []domain.Finding{{
			ID:          "compose.ds007",
			Title:       "Container shares host user namespace",
			Description: fmt.Sprintf("Service %q has userns_mode: host.", svc),
			HowToFix:    "Remove userns_mode: host to enable user namespace remapping.",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkRestart(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "restart")
	if v == "" || v == "no" {
		return []domain.Finding{{
			ID:          "compose.ds008",
			Title:       "Container restart policy not set",
			Description: fmt.Sprintf("Service %q has no restart policy or is set to 'no'.", svc),
			HowToFix:    "Set restart: unless-stopped to ensure container restarts after crashes.",
			Severity:    domain.SeverityLow,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkUser(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "user")
	if v == "" || v == "0" || v == "root" || v == "0:0" || v == "root:root" {
		desc := fmt.Sprintf("Service %q does not specify a user (defaults to root).", svc)
		if v != "" {
			desc = fmt.Sprintf("Service %q explicitly runs as root (user: %s).", svc, v)
		}
		return []domain.Finding{{
			ID:          "compose.ds009",
			Title:       "Container runs as root user",
			Description: desc,
			HowToFix:    "Set a non-root UID appropriate for the container image (e.g. user: 1000:1000).",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkMemoryLimit(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "deploy.resources.limits.memory")
	if v == "" {
		v, _ = f.GetFieldRaw(svc, "mem_limit")
	}
	if v == "" {
		return []domain.Finding{{
			ID:          "compose.ds010",
			Title:       "Container has no memory limit",
			Description: fmt.Sprintf("Service %q has no memory limit configured.", svc),
			HowToFix:    `Add deploy.resources.limits.memory (e.g. "512M") to prevent resource exhaustion.`,
			Severity:    domain.SeverityLow,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkCPULimit(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "deploy.resources.limits.cpus")
	if v == "" {
		v, _ = f.GetFieldRaw(svc, "cpus")
	}
	if v == "" {
		return []domain.Finding{{
			ID:          "compose.ds011",
			Title:       "Container has no CPU limit",
			Description: fmt.Sprintf("Service %q has no CPU limit configured.", svc),
			HowToFix:    `Add deploy.resources.limits.cpus (e.g. "1.0") to prevent CPU starvation.`,
			Severity:    domain.SeverityLow,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkHealthcheck(f *compose.File, svc string, project Project) []domain.Finding {
	// healthcheck is a mapping, not a scalar. Use GetFieldStrings to check existence.
	levels := []string{"healthcheck", "healthcheck.test", "healthcheck.interval"}
	for _, p := range levels {
		v, err := f.GetFieldStrings(svc, p)
		if err == nil && len(v) > 0 {
			return nil
		}
	}
	port := detectContainerPort(f, svc)
	meta := composeMeta(project, svc)
	if port != "" {
		meta["container_port"] = port
	}
	return []domain.Finding{{
		ID:          "compose.ds012",
		Title:       "Container has no healthcheck",
		Description: fmt.Sprintf("Service %q has no healthcheck configured.", svc),
		HowToFix:    `Add a healthcheck block with test, interval, timeout, and retries.`,
		Severity:    domain.SeverityLow,
		Source:      domain.SourceCompose,
		Service:     svc,
		Remediation: domain.RemediationUnavailable,
		Metadata:    meta,
	}}
}

func detectContainerPort(f *compose.File, svc string) string {
	// Try ports mapping: "host:container" or "container" format
	ports, err := f.GetFieldStrings(svc, "ports")
	if err == nil {
		for _, p := range ports {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// "host:container" format
			if idx := strings.LastIndex(p, ":"); idx >= 0 {
				container := p[idx+1:]
				// strip /tcp or /udp suffix
				if slash := strings.Index(container, "/"); slash >= 0 {
					container = container[:slash]
				}
				if _, err := fmt.Sscanf(container, "%d", new(int)); err == nil {
					return container
				}
			}
			// bare port number
			if _, err := fmt.Sscanf(p, "%d", new(int)); err == nil {
				return p
			}
		}
	}
	// Try expose directive
	expose, err := f.GetFieldStrings(svc, "expose")
	if err == nil && len(expose) > 0 {
		p := strings.TrimSpace(expose[0])
		if slash := strings.Index(p, "/"); slash >= 0 {
			p = p[:slash]
		}
		return p
	}
	return ""
}

func checkTmpfs(f *compose.File, svc string, project Project) []domain.Finding {
	tmps, err := f.GetFieldStrings(svc, "tmpfs")
	if err != nil || len(tmps) == 0 {
		return nil
	}
	hasNoexec := false
	for _, t := range tmps {
		if strings.Contains(t, "noexec") {
			hasNoexec = true
			break
		}
	}
	if !hasNoexec {
		return []domain.Finding{{
			ID:          "compose.ds013",
			Title:       "Container tmpfs lacks noexec flag",
			Description: fmt.Sprintf("Service %q tmpfs mounts without noexec flag.", svc),
			HowToFix:    `Add :noexec to tmpfs mount (e.g. "/tmp:noexec").`,
			Severity:    domain.SeverityLow,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkSeccomp(f *compose.File, svc string, project Project) []domain.Finding {
	opts, err := f.GetFieldStrings(svc, "security_opt")
	if err != nil {
		return nil
	}
	for _, o := range opts {
		if strings.Contains(o, "seccomp:unconfined") {
			return []domain.Finding{{
				ID:          "compose.ds014",
				Title:       "Container runs without seccomp profile",
				Description: fmt.Sprintf("Service %q has seccomp:unconfined in security_opt.", svc),
				HowToFix:    `Remove "seccomp:unconfined" from security_opt to enable default seccomp profile.`,
				Severity:    domain.SeverityMedium,
				Source:      domain.SourceCompose,
				Service:     svc,
				Remediation: domain.RemediationUnavailable,
				Metadata:    composeMeta(project, svc),
			}}
		}
	}
	return nil
}

func checkAppArmor(f *compose.File, svc string, project Project) []domain.Finding {
	opts, err := f.GetFieldStrings(svc, "security_opt")
	if err != nil {
		return nil
	}
	for _, o := range opts {
		if strings.Contains(o, "apparmor:unconfined") {
			return []domain.Finding{{
				ID:          "compose.ds015",
				Title:       "Container runs without AppArmor profile",
				Description: fmt.Sprintf("Service %q has apparmor:unconfined in security_opt.", svc),
				HowToFix:    `Remove "apparmor:unconfined" from security_opt to enable default AppArmor profile.`,
				Severity:    domain.SeverityMedium,
				Source:      domain.SourceCompose,
				Service:     svc,
				Remediation: domain.RemediationUnavailable,
				Metadata:    composeMeta(project, svc),
			}}
		}
	}
	return nil
}

func checkNetworkMode(f *compose.File, svc string, project Project) []domain.Finding {
	v, _ := f.GetFieldRaw(svc, "network_mode")
	if v == "host" {
		return []domain.Finding{{
			ID:          "compose.dr001",
			Title:       "Container uses host network mode",
			Description: fmt.Sprintf("Service %q uses network_mode: host, bypassing network isolation.", svc),
			HowToFix:    "Remove network_mode: host and use bridge or overlay networks. For port access, use explicit port mappings.",
			Severity:    domain.SeverityHigh,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	if strings.HasPrefix(v, "container:") {
		other := strings.TrimPrefix(v, "container:")
		return []domain.Finding{{
			ID:          "compose.dr001",
			Title:       "Container shares another container's network",
			Description: fmt.Sprintf("Service %q uses network_mode: container:%s, sharing its network stack.", svc, other),
			HowToFix:    "Use bridge or overlay networks with explicit port mappings instead of sharing another container's network.",
			Severity:    domain.SeverityMedium,
			Source:      domain.SourceCompose,
			Service:     svc,
			Remediation: domain.RemediationUnavailable,
			Metadata:    composeMeta(project, svc),
		}}
	}
	return nil
}

func checkPortBinding(f *compose.File, svc string, project Project) []domain.Finding {
	ports, err := f.GetFieldStrings(svc, "ports")
	if err != nil || len(ports) == 0 {
		return nil
	}
	for _, p := range ports {
		// Ports like "8080:80" or with 0.0.0.0: prefix bind to all interfaces
		if colonIdx := strings.Index(p, ":"); colonIdx > 0 {
			first := p[:colonIdx]
			if first == "0.0.0.0" || isNumeric(first) {
				return []domain.Finding{{
					ID:          "compose.dr002",
					Title:       "Container exposes ports on all interfaces",
					Description: fmt.Sprintf("Service %q port mapping %q binds to 0.0.0.0.", svc, p),
					HowToFix:    `Prefix port mapping with "127.0.0.1:" to restrict to localhost, or remove the mapping.`,
					Severity:    domain.SeverityMedium,
					Source:      domain.SourceCompose,
					Service:     svc,
					Remediation: domain.RemediationUnavailable,
					Metadata:    composeMeta(project, svc),
				}}
			}
		}
	}
	// Check long-syntax ports (mapping nodes with host_ip/published)
	portsNode := f.GetFieldNode(svc, "ports")
	if portsNode != nil && portsNode.Kind == 3 { // yaml.SequenceNode
		for _, item := range portsNode.Content {
			if item.Kind != 4 { // yaml.MappingNode
				continue
			}
			hostIP := ""
			published := ""
			for i := 0; i < len(item.Content)-1; i += 2 {
				key := item.Content[i].Value
				val := item.Content[i+1].Value
				switch key {
				case "host_ip":
					hostIP = val
				case "published":
					published = val
				}
			}
			if hostIP == "0.0.0.0" || (hostIP == "" && published != "") {
				desc := fmt.Sprintf("Service %q port long-syntax binding exposes on all interfaces.", svc)
				if published != "" {
					desc = fmt.Sprintf("Service %q port %q long-syntax binding exposes on all interfaces.", svc, published)
				}
				return []domain.Finding{{
					ID:          "compose.dr002",
					Title:       "Container exposes ports on all interfaces",
					Description: desc,
					HowToFix:    `Set host_ip: "127.0.0.1" in port long-syntax to restrict to localhost, or remove the mapping.`,
					Severity:    domain.SeverityMedium,
					Source:      domain.SourceCompose,
					Service:     svc,
					Remediation: domain.RemediationUnavailable,
					Metadata:    composeMeta(project, svc),
				}}
			}
		}
	}
	return nil
}

func checkVolumeRO(f *compose.File, svc string, project Project) []domain.Finding {
	vols, err := f.GetFieldStrings(svc, "volumes")
	if err != nil || len(vols) == 0 {
		return nil
	}
	for _, v := range vols {
		if !strings.Contains(v, ":ro") && !strings.Contains(v, ":") {
			// Named volumes with no suffix are fine (Docker manages them)
			continue
		} else if !strings.Contains(v, ":ro") {
			return []domain.Finding{{
				ID:          "compose.dr003",
				Title:       "Container mounts volumes as read-write",
				Description: fmt.Sprintf("Service %q mounts volume %q without :ro flag.", svc, v),
				HowToFix:    `Append ":ro" to volume mount when write access is not required.`,
				Severity:    domain.SeverityLow,
				Source:      domain.SourceCompose,
				Service:     svc,
				Remediation: domain.RemediationUnavailable,
				Metadata:    composeMeta(project, svc),
			}}
		}
	}
	return nil
}
