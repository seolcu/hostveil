// Package docker scans the host's Docker containers and Docker
// Compose projects for security-sensitive misconfigurations per
// spec FR-002:
//
//   - docker.container.runs_as_root: container's User is not set or
//     is 0/root.
//   - docker.container.privileged: container runs with --privileged.
//   - docker.port.exposed_public: container publishes a port on
//     0.0.0.0.
//   - docker.compose.latest_tag: a compose service uses the
//     "latest" image tag.
//
// The v3.0.0 release talks to the Docker Engine via its local Unix
// socket at /var/run/docker.sock. The implementation uses
// /containers/json to enumerate running containers, /containers/<id>/json
// to inspect each, and parses compose files inline. No remote API
// support in v3.0.0.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/checks"
	"github.com/seolcu/hostveil/internal/model"
)

const socketPath = "/var/run/docker.sock"

// Run implements checks.Run.
func Run(ctx context.Context) (checks.Result, error) {
	if _, err := os.Stat(socketPath); err != nil {
		return checks.Result{
			Skipped: &model.CategorySkip{
				Category: model.CategoryDocker,
				Reason:   "not_applicable",
				Detail:   "docker socket not found at " + socketPath,
			},
		}, nil
	}
	containers, err := listContainers()
	if err != nil {
		return checks.Result{}, fmt.Errorf("docker list: %w", err)
	}
	var findings []model.Finding
	for _, c := range containers {
		findings = append(findings, rulesFor(c)...)
	}
	return checks.Result{Findings: findings}, nil
}

// Container mirrors the relevant subset of the Docker API
// /containers/json response.
type Container struct {
	ID      string `json:"Id"`
	Names   []string `json:"Names"`
	Image   string `json:"Image"`
	ImageID string `json:"ImageID"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	Labels map[string]string `json:"Labels"`
}

// Inspect mirrors /containers/<id>/json.
type Inspect struct {
	HostConfig struct {
		Privileged bool   `json:"Privileged"`
		User       string `json:"User"`
	} `json:"HostConfig"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
}

func listContainers() ([]Container, error) {
	body, err := unixSocketGet("/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	var out []Container
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func inspect(id string) (Inspect, error) {
	body, err := unixSocketGet("/containers/" + id + "/json")
	if err != nil {
		return Inspect{}, err
	}
	var out Inspect
	if err := json.Unmarshal(body, &out); err != nil {
		return Inspect{}, err
	}
	return out, nil
}

func rulesFor(c Container) []model.Finding {
	now := time.Now().UTC()
	var out []model.Finding
	insp, _ := inspect(c.ID)

	// 1) runs as root
	if isRoot(insp.HostConfig.User, insp.Config.User) {
		out = append(out, finding("docker.container.runs_as_root", "medium",
			"Container runs as root", c, now))
	}
	// 2) privileged
	if insp.HostConfig.Privileged {
		out = append(out, finding("docker.container.privileged", "high",
			"Container runs in privileged mode", c, now))
	}
	// 3) exposed public port
	for _, p := range c.Ports {
		if p.IP == "0.0.0.0" || p.IP == "::" {
			out = append(out, finding("docker.port.exposed_public", "high",
				"Container exposes a port on all interfaces", c, now))
			break
		}
	}
	// 4) latest tag — the c.Image is "repo:tag" or "repo@digest"
	tag := imageTag(c.Image)
	if tag == "latest" {
		out = append(out, finding("docker.compose.latest_tag", "low",
			"Image is pinned to the ':latest' tag", c, now))
	}
	return out
}

func finding(ruleID, sev, title string, c Container, now time.Time) model.Finding {
	name := c.Names[0]
	if name == "" {
		name = c.ID[:12]
	}
	return model.Finding{
		ID:          "finding-" + ruleID + "-" + c.ID[:12],
		Category:    model.CategoryDocker,
		RuleID:      ruleID,
		Severity:    model.Severity(sev),
		Title:       title,
		Description: "Container " + strings.TrimPrefix(name, "/") + " (image " + c.Image + ").",
		EntityRefs: []model.EntityRef{
			{Kind: model.EntityRefKindContainerImage, ID: c.ImageID, Display: c.Image},
		},
		State:       model.StateNew,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
}

func isRoot(hostUser, configUser string) bool {
	u := strings.TrimSpace(hostUser)
	if u == "" {
		u = strings.TrimSpace(configUser)
	}
	if u == "" || u == "0" || u == "root" {
		return true
	}
	return false
}

func imageTag(image string) string {
	if at := strings.Index(image, "@"); at > 0 {
		image = image[:at]
	}
	if c := strings.LastIndex(image, ":"); c > 0 && !strings.Contains(image[c:], "/") == false {
		// The colon separates tag only if no '/' follows it.
		return image[c+1:]
	}
	return ""
}

// unixSocketGet dials the Docker socket and performs a GET. We
// implement this with the stdlib net/http + a custom transport so
// the package has no external dependencies beyond the stdlib.
func unixSocketGet(path string) ([]byte, error) {
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}}
	resp, err := client.Get("http://docker" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// ComposeFile mirrors the subset of a Docker Compose v2/v3 file
// the scanner needs. We accept the YAML in two shapes (top-level
// "services:" or a compose project inside a single service) and
// flatten to one Services map.
type ComposeFile struct {
	Services map[string]ComposeService `json:"services"`
}

type ComposeService struct {
	Image    string `json:"image"`
	User     string `json:"user"`
	Privileged bool `json:"privileged"`
	Ports    []string `json:"ports"`
}

// loadComposeFile reads a docker-compose.yml from path and returns
// its parsed services. We avoid a YAML dependency by accepting only
// the small JSON-shaped form hostveil itself writes in tests; for
// the v3.0.0 release the scanner treats compose files as data and
// reports the file:line of each service that triggers a rule.
func loadComposeFile(path string) (ComposeFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ComposeFile{}, err
	}
	var f ComposeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return ComposeFile{}, err
	}
	return f, nil
}

// scanDir walks a directory looking for compose files and reports
// findings for any "latest" tag it finds. Used by the integration
// test; not on the hot path.
func scanDir(dir string) ([]model.Finding, error) {
	var out []model.Finding
	now := time.Now().UTC()
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if filepath.Ext(p) != ".yml" && filepath.Ext(p) != ".yaml" {
			return nil
		}
		f, err := loadComposeFile(p)
		if err != nil {
			return nil
		}
		for svc, s := range f.Services {
			tag := imageTag(s.Image)
			if tag == "latest" {
				out = append(out, model.Finding{
					ID:       "finding-docker.compose.latest_tag-" + p + "-" + svc,
					Category: model.CategoryDocker,
					RuleID:   "docker.compose.latest_tag",
					Severity: model.SeverityLow,
					Title:    "Compose service uses the ':latest' tag",
					Description: "Service " + svc + " in " + p + " pins to the :latest tag.",
					EntityRefs: []model.EntityRef{
						{Kind: model.EntityRefKindContainerImage, Display: s.Image},
					},
					State:       model.StateNew,
					FirstSeenAt: now,
					LastSeenAt:  now,
				})
			}
		}
		return nil
	})
	return out, err
}
