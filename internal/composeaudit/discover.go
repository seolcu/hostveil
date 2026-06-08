package composeaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

type Project struct {
	Name        string
	ComposePath string
}

type composeLSProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func DiscoverProjects() ([]Project, error) {
	ctx, cancel := context.WithTimeout(context.Background(), domain.DockerComposeTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "compose", "ls", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("docker compose ls: %w", err)
	}

	var raw []composeLSProject
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("docker compose ls parse: %w", err)
	}

	var projects []Project
	for _, r := range raw {
		files := strings.Split(r.ConfigFiles, ",")
		path := strings.TrimSpace(files[0])
		if path == "" {
			continue
		}
		projects = append(projects, Project{Name: r.Name, ComposePath: path})
	}
	return projects, nil
}
