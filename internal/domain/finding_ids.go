package domain

// Finding IDs — central constants to avoid string duplication across rules,
// fix engine, and host checks. Always reference these instead of raw strings.

const (
	// Network rules
	FindingNetworkDefaultBridge = "network.default_bridge_used"
	FindingNetworkHostMode      = "network.host_mode"

	// Exposure rules
	FindingExposurePublicBinding       = "exposure.public_binding"
	FindingExposureReverseProxy        = "exposure.reverse_proxy_expected"

	// Permissions rules
	FindingPermissionsPrivileged     = "permissions.privileged"
	FindingPermissionsRootUser       = "permissions.root_user"
	FindingPermissionsSysAdmin       = "permissions.sys_admin_capability"
	FindingPermissionsSensitiveMount = "permissions.sensitive_mount"

	// Runtime rules
	FindingRuntimeNoNewPrivileges = "runtime.no_new_privileges_disabled"
	FindingRuntimeWritableRootfs  = "runtime.writable_rootfs"

	// Sensitive data rules
	FindingSensitiveDefaultSecret = "sensitive.default_secret"
	FindingSensitiveInlineSecret  = "sensitive.inline_secret"

	// Updates rules
	FindingUpdatesLatestTag = "updates.latest_tag"

	// Service-aware rules
	FindingVaultwardenInsecureDomain  = "service.vaultwarden.insecure_domain"
	FindingVaultwardenSignupsAllowed  = "service.vaultwarden.signups_allowed"
	FindingVaultwardenAdminToken      = "service.vaultwarden.admin_token"
	FindingJellyfinPublicURL          = "service.jellyfin.public_url"
	FindingJellyfinRootUser           = "service.jellyfin.root_user"
	FindingJellyfinPrivileged         = "service.jellyfin.privileged"
	FindingPostgresDefaultPassword    = "service.postgres.default_password"
	FindingPostgresNoPassword         = "service.postgres.no_password"
	FindingRedisNoPassword            = "service.redis.no_password"
	FindingRedisPublicBind            = "service.redis.public_bind"
	FindingGitlabRootPassword         = "service.gitlab.root_password"
	FindingTraefikDashboardExposed    = "service.traefik.dashboard_exposed"
	FindingPortainerPublicAccess      = "service.portainer.public_access"
	FindingPiholeUnsecuredWebUI       = "service.pihole.unsecured_web_interface"

	// Host — SSH
	FindingHostSSHRootLogin     = "host.ssh.root_login"
	FindingHostSSHPasswordAuth  = "host.ssh.password_auth"
	FindingHostSSHProtocol      = "host.ssh.protocol"

	// Host — Docker
	FindingHostDockerSocketAccessible = "host.docker.socket_accessible"
	FindingHostDockerDaemonTLS        = "host.docker.daemon_tls"

	// Host — Firewall
	FindingHostFirewallNoActive    = "host.firewall.no_active_firewall"
	FindingHostFirewallDefaultDrop = "host.firewall.default_drop"

	// Host — Kernel
	FindingHostKernelUpdates    = "host.kernel.kernel_updates"
	FindingHostKernelCoreDumps  = "host.kernel.core_dumps"
	FindingHostKernelIPForward  = "host.kernel.ip_forwarding"

	// Host — Filesystem
	FindingHostFilesystemWorldWritable  = "host.filesystem.world_writable_files"
	FindingHostFilesystemSUID           = "host.filesystem.suid_files"
	FindingHostFilesystemSeparateParts  = "host.filesystem.separate_partitions"

	// Host — FIM
	FindingHostFIMNoTool = "host.fim.no_fim_tool"

	// Host — MAC
	FindingHostMACNoAppArmor = "host.mac.no_apparmor"
	FindingHostMACNoSELinux  = "host.mac.no_selinux"

	// Host — Defenses
	FindingHostDefensesFail2ban   = "host.defenses.fail2ban_not_installed"
	FindingHostDefensesRkhunter   = "host.defenses.rkhunter_not_installed"
	FindingHostDefensesAuditd     = "host.defenses.auditd_not_installed"

	// Host — Updates
	FindingHostUpdatesUnattended = "host.updates.unattended_upgrades"
	FindingHostUpdatesReboot     = "host.updates.reboot_required"
)
