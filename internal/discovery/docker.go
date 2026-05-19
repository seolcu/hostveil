package discovery

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type DockerStatus int

const (
	DockerAvailable DockerStatus = iota
	DockerMissing
	DockerPermissionDenied
)

type Project struct {
	Name        string
	ComposePath string
}

type Result struct {
	Status   DockerStatus
	Projects []Project
	Err      string
}

// Discover finds compose files by walking up from the current directory.
// If userMode is true, Docker socket access and host checks are skipped.
func Discover(userMode bool) Result {
	status := DockerAvailable

	// Check Docker availability
	if _, err := exec.LookPath("docker"); err != nil {
		status = DockerMissing
	} else if !userMode {
		cmd := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
		if err := cmd.Run(); err != nil {
			status = DockerPermissionDenied
		}
	}

	// Walk up from current directory looking for compose files
	var projects []Project
	seen := make(map[string]bool)
	dir, _ := os.Getwd()

	for {
		for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil && !seen[path] {
				seen[path] = true
				projects = append(projects, Project{
					Name:        filepath.Base(dir),
					ComposePath: path,
				})
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	if len(projects) > 20 {
		projects = projects[:20]
	}

	return Result{
		Status:   status,
		Projects: projects,
	}
}

func GetHostRuntime(root string) map[string]string {
	info := make(map[string]string)

	if h, err := os.Hostname(); err == nil {
		info["hostname"] = h
	}

	if root == "" {
		root = "/"
	}

	if data, err := os.ReadFile(root + "/proc/loadavg"); err == nil {
		info["load_average"] = strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile(root + "/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			info["uptime"] = parts[0] + "s"
		}
	}

	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output(); err == nil {
		info["docker_version"] = strings.TrimSpace(string(out))
	}

	if _, err := os.Stat(root + "/etc/fail2ban"); err == nil {
		info["fail2ban"] = "Installed"
		if out, err := exec.Command("fail2ban-client", "status").Output(); err == nil {
			info["fail2ban"] = "Enabled"
			output := string(out)
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, "Jail list") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						info["fail2ban_jails"] = fmt.Sprintf("%d", len(strings.Split(strings.TrimSpace(parts[1]), ",")))
					}
				}
			}
		}
	}

	return info
}
