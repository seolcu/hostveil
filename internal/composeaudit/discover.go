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
	Name         string
	ComposePath  string
	ComposePaths []string
}

type composeLSProject struct {
	Name        string `json:"Name"`
	ConfigFiles string `json:"ConfigFiles"`
}

func DiscoverProjects(runner domain.CommandRunner) ([]Project, error) {
	ctx, cancel := context.WithTimeout(context.Background(), domain.DockerComposeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "ls", "--format", "json")
	out, err := runner.Output(cmd)
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
		var paths []string
		for _, f := range files {
			path := strings.TrimSpace(f)
			if path != "" {
				paths = append(paths, path)
			}
		}
		if len(paths) == 0 {
			continue
		}
		projects = append(projects, Project{
			Name:         r.Name,
			ComposePath:  paths[0],
			ComposePaths: paths,
		})
	}
	return projects, nil
}
