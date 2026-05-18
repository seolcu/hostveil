package rules

import (
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

type ServiceKind int

const (
	KindUnknown ServiceKind = iota
	KindVaultwarden
	KindJellyfin
	KindGitea
	KindNextcloud
	KindImmich
	KindTraefik
	KindPortainer
	KindHomeAssistant
	KindPihole
	KindGrafana
	KindNPM // Nginx Proxy Manager
	KindCaddy
	KindAuthentik
	KindPaperless
	KindPostgres
	KindMySQL
	KindRedis
	KindGitlab
	KindUptimeKuma
	KindDuplicati
	KindRestic
	KindBorg
	KindKopia
)

type serviceDetection struct {
	kind    ServiceKind
	images  []string
	names   []string
	label   string
}

var serviceDetections = []serviceDetection{
	{KindVaultwarden, []string{"vaultwarden/server"}, nil, "Vaultwarden"},
	{KindJellyfin, []string{"jellyfin/jellyfin"}, nil, "Jellyfin"},
	{KindGitea, []string{"gitea/gitea"}, nil, "Gitea"},
	{KindNextcloud, []string{"nextcloud"}, nil, "Nextcloud"},
	{KindImmich, []string{"immich/server", "immich"}, nil, "Immich"},
	{KindTraefik, []string{"traefik", "library/traefik"}, nil, "Traefik"},
	{KindPortainer, []string{"portainer/portainer", "portainer/agent"}, nil, "Portainer"},
	{KindHomeAssistant, []string{"homeassistant/home-assistant", "ghcr.io/home-assistant"}, nil, "Home Assistant"},
	{KindPihole, []string{"pihole/pihole"}, nil, "Pi-hole"},
	{KindGrafana, []string{"grafana/grafana"}, nil, "Grafana"},
	{KindNPM, []string{"jc21/nginx-proxy-manager", "nginxproxy/nginx-proxy"}, nil, "Nginx Proxy Manager"},
	{KindCaddy, []string{"caddy", "library/caddy", "caddy/caddy"}, nil, "Caddy"},
	{KindAuthentik, []string{"ghcr.io/goauthentik/server", "authentik"}, nil, "Authentik"},
	{KindPaperless, []string{"ghcr.io/paperless-ngx/paperless-ngx"}, nil, "Paperless"},
	{KindPostgres, []string{"postgres", "library/postgres"}, nil, "PostgreSQL"},
	{KindMySQL, []string{"mysql", "library/mysql", "mariadb", "library/mariadb"}, nil, "MySQL"},
	{KindRedis, []string{"redis", "library/redis"}, nil, "Redis"},
	{KindGitlab, []string{"gitlab/gitlab-ce", "gitlab/gitlab-ee"}, nil, "GitLab"},
	{KindUptimeKuma, []string{"louislam/uptime-kuma"}, nil, "Uptime Kuma"},
	{KindDuplicati, []string{"duplicati/duplicati", "linuxserver/duplicati"}, nil, "Duplicati"},
	{KindRestic, []string{"restic/restic"}, nil, "Restic"},
	{KindBorg, []string{"borgbackup", "borgmatic"}, nil, "Borg"},
	{KindKopia, []string{"kopia/kopia"}, nil, "Kopia"},
}

func detectServiceKind(svc compose.Service, name string) (ServiceKind, string) {
	img := svc.Image
	for _, d := range serviceDetections {
		for _, pattern := range d.images {
			if strings.Contains(strings.ToLower(img), pattern) {
				return d.kind, d.label
			}
		}
		for _, pattern := range d.names {
			if strings.Contains(strings.ToLower(name), pattern) {
				return d.kind, d.label
			}
		}
	}
	return KindUnknown, ""
}

type serviceFindingDef struct {
	ID          string
	Axis        domain.Axis
	Severity    domain.Severity
	Remediation domain.RemediationKind
	Title       string
	Description string // %s = service name, %d = port
	WhyRisky    string
	HowToFix    string
	Condition   func(svc compose.Service) bool
	EvidenceKey string // env var or config key to capture
}

var serviceFindings = map[ServiceKind][]serviceFindingDef{
	KindVaultwarden: {
		{
			ID:          "service.vaultwarden.insecure_domain",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "Vaultwarden domain is configured for public HTTP",
			Description: "%s sets DOMAIN to an HTTP URL instead of HTTPS.",
			WhyRisky:    "Vaultwarden handles passwords and secrets. Without HTTPS, credentials and session tokens are transmitted in cleartext.",
			HowToFix:    "Set DOMAIN to an HTTPS URL and place Vaultwarden behind a reverse proxy that terminates TLS.\n  environment:\n    DOMAIN: https://vault.yourdomain.com",
			Condition:   func(svc compose.Service) bool { return hasEnvPrefixed(svc, "DOMAIN", "http://") },
			EvidenceKey: "DOMAIN",
		},
		{
			ID:          "service.vaultwarden.signups_allowed",
			Axis:        domain.AxisExcessivePermissions,
			Severity:    domain.SeverityMedium,
			Remediation: domain.RemediationReview,
			Title:       "Vaultwarden has open registration enabled",
			Description: "%s has SIGNUPS_ALLOWED set to true.",
			WhyRisky:    "Open registration allows anyone to create an account. For single-user or family deployments, disable registration after initial setup.",
			HowToFix:    "Set SIGNUPS_ALLOWED to false after creating your account:\n  environment:\n    SIGNUPS_ALLOWED: \"false\"",
			Condition:   func(svc compose.Service) bool { return hasEnvValue(svc, "SIGNUPS_ALLOWED", "true") },
			EvidenceKey: "SIGNUPS_ALLOWED",
		},
		{
			ID:          "service.vaultwarden.admin_token",
			Axis:        domain.AxisSensitiveData,
			Severity:    domain.SeverityMedium,
			Remediation: domain.RemediationReview,
			Title:       "Vaultwarden admin token is set via environment",
			Description: "%s sets ADMIN_TOKEN as an inline environment variable.",
			WhyRisky:    "The admin panel token grants full access to Vaultwarden settings. Inline env vars can leak into shell history and CI logs.",
			HowToFix:    "Use a Docker secret for ADMIN_TOKEN:\n  secrets:\n    - admin_token\n  environment:\n    ADMIN_TOKEN_FILE: /run/secrets/admin_token",
			Condition:   func(svc compose.Service) bool { return hasEnv(svc, "ADMIN_TOKEN") },
			EvidenceKey: "ADMIN_TOKEN",
		},
	},

	KindJellyfin: {
		{
			ID:          "service.jellyfin.public_url",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityMedium,
			Remediation: domain.RemediationReview,
			Title:       "Jellyfin PublishedServerUrl is set to an HTTP URL",
			Description: "%s has JELLYFIN_PublishedServerUrl configured.",
			WhyRisky:    "Jellyfin streams media content. A misconfigured published URL can leak the internal server address or expose the service without TLS.",
			HowToFix:    "Ensure the published URL uses HTTPS and the correct external domain.",
			Condition:   func(svc compose.Service) bool { return hasEnvPrefixed(svc, "JELLYFIN_PublishedServerUrl", "http://") },
			EvidenceKey: "JELLYFIN_PublishedServerUrl",
		},
		{
			ID:          "service.jellyfin.root_user",
			Axis:        domain.AxisExcessivePermissions,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "Jellyfin runs as root",
			Description: "%s runs as the root user.",
			WhyRisky:    "Jellyfin does not need root access. A compromised Jellyfin process with root privileges can take over the host.",
			HowToFix:    "Run Jellyfin with a non-root user:\n  user: \"1000:1000\"",
			Condition:   func(svc compose.Service) bool { return svc.User == "root" || svc.User == "" || svc.User == "0:0" },
			EvidenceKey: "user",
		},
		{
			ID:          "service.jellyfin.privileged",
			Axis:        domain.AxisExcessivePermissions,
			Severity:    domain.SeverityCritical,
			Remediation: domain.RemediationReview,
			Title:       "Jellyfin runs in privileged mode",
			Description: "%s has privileged: true.",
			WhyRisky:    "Privileged mode grants unrestricted host access. Jellyfin typically only needs hardware acceleration access, not full privilege.",
			HowToFix:    "Replace privileged: true with specific device mappings:\n  devices:\n    - /dev/dri:/dev/dri\n  group_add:\n    - \"44\"",
			Condition:   func(svc compose.Service) bool { return svc.Privileged },
			EvidenceKey: "privileged",
		},
	},

	KindPostgres: {
		{
			ID:          "service.postgres.default_password",
			Axis:        domain.AxisSensitiveData,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "PostgreSQL uses a default or weak password",
			Description: "%s has POSTGRES_PASSWORD set.",
			WhyRisky:    "Databases with weak or default passwords are prime targets for data breaches and ransomware.",
			HowToFix:    "Use a strong, unique password:\n  environment:\n    POSTGRES_PASSWORD: <generate a strong password>\nOr use POSTGRES_PASSWORD_FILE with a Docker secret.",
			Condition:   func(svc compose.Service) bool { return hasEnv(svc, "POSTGRES_PASSWORD") },
			EvidenceKey: "POSTGRES_PASSWORD",
		},
		{
			ID:          "service.postgres.no_password",
			Axis:        domain.AxisSensitiveData,
			Severity:    domain.SeverityCritical,
			Remediation: domain.RemediationManual,
			Title:       "PostgreSQL has no password set",
			Description: "%s does not set POSTGRES_PASSWORD.",
			WhyRisky:    "A database without authentication allows anyone who can reach it to read and write all data.",
			HowToFix:    "Set a strong POSTGRES_PASSWORD in the environment.",
			Condition:   func(svc compose.Service) bool { return !hasEnv(svc, "POSTGRES_PASSWORD") && !hasEnv(svc, "POSTGRES_PASSWORD_FILE") },
		},
	},

	KindRedis: {
		{
			ID:          "service.redis.no_password",
			Axis:        domain.AxisSensitiveData,
			Severity:    domain.SeverityCritical,
			Remediation: domain.RemediationManual,
			Title:       "Redis has no password configured",
			Description: "%s does not set REDIS_PASSWORD or use a Redis ACL.",
			WhyRisky:    "Redis without authentication allows anyone who can reach the port to read, write, or flush the entire dataset.",
			HowToFix:    "Set a Redis password via the command or REDIS_PASSWORD env var:\n  command: redis-server --requirepass <strong-password>",
			Condition:   func(svc compose.Service) bool { return !hasEnv(svc, "REDIS_PASSWORD") },
		},
		{
			ID:          "service.redis.public_bind",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationAuto,
			Title:       "Redis port is exposed on a public interface",
			Description: "%s publishes the Redis port on %d to a public interface.",
			WhyRisky:    "Exposing Redis to the internet without authentication allows anyone to read, write, or flush the entire dataset.",
			HowToFix:    "Bind Redis port 6379 to localhost or an internal Docker network.",
			Condition:   func(svc compose.Service) bool { return hasPublicPort(svc, 6379) },
		},
	},

	KindGitlab: {
		{
			ID:          "service.gitlab.root_password",
			Axis:        domain.AxisSensitiveData,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "GitLab root password is set via environment",
			Description: "%s uses GITLAB_ROOT_PASSWORD as an inline environment variable.",
			WhyRisky:    "Inline passwords in compose files are visible to anyone with file access and can leak into backups and CI.",
			HowToFix:    "Use GITLAB_ROOT_PASSWORD_FILE with a Docker secret instead.",
			Condition:   func(svc compose.Service) bool { return hasEnv(svc, "GITLAB_ROOT_PASSWORD") },
			EvidenceKey: "GITLAB_ROOT_PASSWORD",
		},
	},

	KindTraefik: {
		{
			ID:          "service.traefik.dashboard_exposed",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "Traefik dashboard may be exposed externally",
			Description: "%s exposes the Traefik dashboard port (8080) on a public interface.",
			WhyRisky:    "The Traefik dashboard reveals your entire reverse proxy configuration, including all backend service URLs and TLS settings.",
			HowToFix:    "Bind the dashboard port to localhost and enable authentication:\n  ports:\n    - \"127.0.0.1:8080:8080\"",
			Condition:   func(svc compose.Service) bool { return hasPublicPort(svc, 8080) },
		},
	},

	KindPortainer: {
		{
			ID:          "service.portainer.public_access",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityHigh,
			Remediation: domain.RemediationReview,
			Title:       "Portainer UI is accessible from the network",
			Description: "%s exposes the Portainer UI port (9000 or 9443).",
			WhyRisky:    "Portainer provides full Docker management. Exposing it without proper authentication gives attackers control over all containers.",
			HowToFix:    "Restrict Portainer access to localhost or use an internal network with a reverse proxy for TLS.",
			Condition:   func(svc compose.Service) bool { return hasPublicPort(svc, 9000) || hasPublicPort(svc, 9443) },
		},
	},

	KindPihole: {
		{
			ID:          "service.pihole.unsecured_web_interface",
			Axis:        domain.AxisUnnecessaryExposure,
			Severity:    domain.SeverityMedium,
			Remediation: domain.RemediationManual,
			Title:       "Pi-hole web interface has no password configured",
			Description: "%s may have the web interface exposed without authentication.",
			WhyRisky:    "The Pi-hole web interface controls DNS filtering. Unauthorized access can disable ad-blocking or modify DNS settings.",
			HowToFix:    "Set WEBPASSWORD environment variable:\n  environment:\n    WEBPASSWORD: <strong-password>",
			Condition:   func(svc compose.Service) bool { return !hasEnv(svc, "WEBPASSWORD") },
		},
	},
}

type ServiceAwareRule struct{}

func (r *ServiceAwareRule) Name() string { return "service_aware" }

func (r *ServiceAwareRule) Scan(svc compose.Service, name string, cf *compose.ComposeFile) []domain.Finding {
	kind, _ := detectServiceKind(svc, name)
	if kind == KindUnknown {
		return nil
	}

	defs, ok := serviceFindings[kind]
	if !ok {
		return nil
	}

	var findings []domain.Finding
	for _, def := range defs {
		if def.Condition != nil && !def.Condition(svc) {
			continue
		}

		desc := strings.ReplaceAll(def.Description, "%s", name)
		if strings.Contains(desc, "%d") {
			// Find first public port for context
			for _, p := range svc.Ports {
				desc = strings.Replace(desc, "%d", itoa(p.Target), 1)
				break
			}
		}

		f := domain.Finding{
			ID:          def.ID,
			Axis:        def.Axis,
			Severity:    def.Severity,
			Scope:       domain.ScopeService,
			Source:      domain.SourceNativeCompose,
			Subject:     name,
			Service:     name,
			Title:       def.Title,
			Description: desc,
			WhyRisky:    def.WhyRisky,
			HowToFix:    def.HowToFix,
			Evidence:    make(map[string]string),
			Remediation: def.Remediation,
		}

		if def.EvidenceKey != "" {
			if val, ok := svc.Environment[def.EvidenceKey]; ok {
				f.Evidence[def.EvidenceKey] = val
			}
		}

		findings = append(findings, f)
	}

	return findings
}

func hasEnv(svc compose.Service, key string) bool {
	_, ok := svc.Environment[key]
	return ok
}

func hasEnvValue(svc compose.Service, key, val string) bool {
	v, ok := svc.Environment[key]
	return ok && strings.EqualFold(v, val)
}

func hasEnvPrefixed(svc compose.Service, key, prefix string) bool {
	v, ok := svc.Environment[key]
	return ok && strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix))
}

func hasPublicPort(svc compose.Service, port uint16) bool {
	for _, p := range svc.Ports {
		if p.Target == port && (p.HostIP == "" || p.HostIP == "0.0.0.0") {
			return true
		}
	}
	return false
}
