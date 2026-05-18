package discovery

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type DockerStatus int

const (
	DockerAvailable DockerStatus = iota
	DockerMissing
	DockerPermissionDenied
)

type Project struct {
	Name          string
	ComposePath   string
	ServiceCount  int
}

type Result struct {
	Status    DockerStatus
	Projects  []Project
	Err       string
}

func Discover() Result {
	// Check if Docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return Result{Status: DockerMissing}
	}

	// Test Docker access
	cmd := exec.Command("docker", "info", "--format", "{{.ServerVersion}}")
	if err := cmd.Run(); err != nil {
		return Result{Status: DockerPermissionDenied, Err: err.Error()}
	}

	// Discover compose files recursively from common locations
	var projects []Project
	locations := []string{".", "/home", "/opt", "/srv", "/docker"}

	for _, loc := range locations {
		found, err := findComposeFiles(loc)
		if err == nil {
			projects = append(projects, found...)
		}
	}

	return Result{
		Status:   DockerAvailable,
		Projects: projects,
	}
}

func findComposeFiles(root string) ([]Project, error) {
	var projects []Project

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		dir := root + "/" + entry.Name()
		composePath := ""
		for _, name := range []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"} {
			if _, err := os.Stat(dir + "/" + name); err == nil {
				composePath = dir + "/" + name
				break
			}
		}

		if composePath != "" {
			projects = append(projects, Project{
				Name:         entry.Name(),
				ComposePath:  composePath,
			})
		}

		// Recurse one level
		if len(projects) == 0 {
			sub, _ := findComposeFiles(dir)
			projects = append(projects, sub...)
		}
	}

	if len(projects) > 10 {
		projects = projects[:10]
	}

	return projects, nil
}

func GetHostRuntime(root string) map[string]string {
	info := make(map[string]string)

	if h, err := os.Hostname(); err == nil {
		info["hostname"] = h
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

	// Docker version
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").Output(); err == nil {
		info["docker_version"] = strings.TrimSpace(string(out))
	}

	// Fail2ban
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
