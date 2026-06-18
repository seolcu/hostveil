package model

import "time"

// ConfigFileFormat is the locked enum for ConfigFile.format.
type ConfigFileFormat string

const (
	FormatSSHDConfig       ConfigFileFormat = "sshd_config"
	FormatDockerComposeYAML ConfigFileFormat = "docker_compose_yaml"
	FormatNginxConf        ConfigFileFormat = "nginx_conf"
	FormatCaddyfile        ConfigFileFormat = "caddyfile"
	FormatSysctlConf       ConfigFileFormat = "sysctl_conf"
	FormatPackageManagerList ConfigFileFormat = "package_manager_list"
	FormatOther            ConfigFileFormat = "other"
)

// ConfigFile is a file on disk the program inspects.
type ConfigFile struct {
	ID         string           `json:"id"`
	HostID     string           `json:"host_id"`
	Path       string           `json:"path"`
	OwnerUser  string           `json:"owner_user,omitempty"`
	OwnerGroup string           `json:"owner_group,omitempty"`
	Format     ConfigFileFormat `json:"format"`
	Settings   []Setting        `json:"settings,omitempty"`
	LastSeenAt time.Time        `json:"last_seen_at"`
	ContentHash string         `json:"content_hash"`
}
