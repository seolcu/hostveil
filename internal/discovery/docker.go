package discovery

import (
	"encoding/json"
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
}

// Discover finds running compose projects via `docker compose ls`.
func Discover() Result {
	if _, err := exec.LookPath("docker"); err != nil {
		return Result{Status: DockerMissing}
	}

	out, err := exec.Command("docker", "compose", "ls", "--format", "json").Output()
	if err != nil {
		return Result{Status: DockerPermissionDenied}
	}
	return parseDockerComposeLS(string(out))
}

type composeLSProject struct {
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ConfigFiles string `json:"ConfigFiles"`
}

func parseDockerComposeLS(output string) Result {
	// Handle empty output (no projects)
	output = strings.TrimSpace(output)
	if output == "" {
		return Result{Status: DockerAvailable}
	}

	var raw []composeLSProject
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return Result{Status: DockerAvailable}
	}

	var projects []Project
	seen := make(map[string]bool)
	for _, p := range raw {
		files := strings.Split(p.ConfigFiles, ",")
		if len(files) == 0 {
			continue
		}
		path := strings.TrimSpace(files[0])
		if !strings.HasPrefix(path, "/") {
			abs, err := filepath.Abs(path)
			if err == nil {
				path = abs
			}
		}
		if seen[path] {
			continue
		}
		seen[path] = true
		projects = append(projects, Project{
			Name:        p.Name,
			ComposePath: path,
		})
	}
	if len(projects) > 20 {
		projects = projects[:20]
	}
	return Result{
		Status:   DockerAvailable,
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

func RefreshRuntimeHostInfo(root string) (uptime, loadAvg string) {
	if root == "" {
		root = "/"
	}
	if data, err := os.ReadFile(root + "/proc/loadavg"); err == nil {
		loadAvg = strings.TrimSpace(string(data))
	}
	if data, err := os.ReadFile(root + "/proc/uptime"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) > 0 {
			uptime = parts[0] + "s"
		}
	}
	return
}
