package fix

import (
	"fmt"
	"os/exec"
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
				service := ctx.Finding.Service
				if service == "" {
					return fmt.Errorf("no service name in finding")
				}
				// Pull the latest image
				pullArgs := []string{"compose", "-f", composePath, "pull"}
				if service != "" {
					pullArgs = append(pullArgs, service)
				}
				if out, err := exec.Command("docker", pullArgs...).CombinedOutput(); err != nil {
					return fmt.Errorf("docker compose pull failed: %s", string(out))
				}
				// Redeploy the service
				upArgs := []string{"compose", "-f", composePath, "up", "-d", "--force-recreate"}
				if service != "" {
					upArgs = append(upArgs, service)
				}
				if out, err := exec.Command("docker", upArgs...).CombinedOutput(); err != nil {
					return fmt.Errorf("docker compose up failed: %s", string(out))
				}
				return nil
			},
		}},
	})
}
