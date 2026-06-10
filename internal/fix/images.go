package fix

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
)

func registerImageFixes(r *Registry) {
	r.Register(&Fix{
		FindingID: "trivy.cve-*",
		Label:     "Pull latest image and redeploy service",
		Actions: []Action{{
			Type:    ActionExec,
			Label:   "Pull latest image and redeploy",
			Warning: "This will restart the service with the latest image. The CVE may still be present if the image maintainer has not released a fix.",
			Apply: func(ctx Context) error {
				if ctx.Finding == nil {
					return fmt.Errorf("no finding provided")
				}
				fixedVer := ctx.Finding.Evidence["fixed_version"]
				if fixedVer == "" {
					return fmt.Errorf("no fix available yet — upstream has not released a patched version")
				}
				composePath := ctx.Finding.Metadata["compose_path"]
				if composePath == "" {
					return fmt.Errorf("no compose path in finding metadata")
				}
				image := ctx.Finding.Service
				if image == "" {
					return fmt.Errorf("no image in finding service field")
				}
				// Resolve the compose service that uses this image.
				// CVE findings store the image name in Service, not the compose service name.
				serviceName, err := resolveServiceForImage(composePath, image)
				if err != nil {
					return fmt.Errorf("resolve service for image %q in %s: %w", image, composePath, err)
				}
				// Pull the image. Prefer `docker compose pull <service>` if we know the
				// service. Otherwise fall back to `docker pull <image>`.
				if serviceName != "" {
					pullArgs := []string{"compose", "-f", composePath, "pull", serviceName}
					if out, err := exec.Command("docker", pullArgs...).CombinedOutput(); err != nil {
						return fmt.Errorf("docker compose pull %s failed: %s", serviceName, string(out))
					}
				} else {
					if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
						return fmt.Errorf("docker pull %s failed: %s", image, string(out))
					}
				}
				// Redeploy. If we know the service, recreate only it. Otherwise
				// recreate the whole project so all containers pick up the new image.
				var upArgs []string
				if serviceName != "" {
					upArgs = []string{"compose", "-f", composePath, "up", "-d", "--force-recreate", serviceName}
				} else {
					upArgs = []string{"compose", "-f", composePath, "up", "-d", "--force-recreate"}
				}
				if out, err := exec.Command("docker", upArgs...).CombinedOutput(); err != nil {
					return fmt.Errorf("docker compose up failed: %s", string(out))
				}
				return nil
			},
		}},
	})
}

// resolveServiceForImage returns the compose service name in composePath whose
// `image` field matches the given image. Returns "" if no service matches
// (caller should fall back to a project-wide pull/recreate).
func resolveServiceForImage(composePath, image string) (string, error) {
	f, err := compose.Open(composePath)
	if err != nil {
		return "", err
	}
	services, err := f.ServiceNames()
	if err != nil {
		return "", err
	}
	for _, svc := range services {
		img, _ := f.GetFieldRaw(svc, "image")
		if imagesMatch(img, image) {
			return svc, nil
		}
	}
	return "", nil
}

// imagesMatch returns true if the two image references refer to the same
// image. Docker's default tag is ":latest" when no tag is specified, so
// "nginx" and "nginx:latest" are considered the same.
func imagesMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if !strings.Contains(a, ":") {
		a = a + ":latest"
	}
	if !strings.Contains(b, ":") {
		b = b + ":latest"
	}
	return a == b
}
