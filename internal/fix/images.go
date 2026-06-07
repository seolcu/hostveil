package fix

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
)

func registerImageFixes(r *Registry) {
	r.Register(&Fix{
		FindingID: "trivy.cve-*",
		Label:     "Update image to patched version",
		Actions: []Action{
			{
				Type:    ActionEdit,
				Label:   "Update image tag and pull",
				Warning: "Updating the image may break API compatibility. Verify after applying.",
				Apply: func(ctx Context) error {
					return fixImageCVE(ctx)
				},
			},
		},
	})
}

func fixImageCVE(ctx Context) error {
	ev := ctx.Finding.Evidence
	image := ctx.Finding.Service
	if image == "" {
		return fmt.Errorf("no image name in finding")
	}
	fixedVer := ev["fixed_version"]
	if fixedVer == "" {
		return fmt.Errorf("no fixed version available")
	}

	// Step 1: Pull the image at the fixed version (fallback to latest)
	pullRef := fmt.Sprintf("%s:%s", image, fixedVer)
	if err := exec.Command("docker", "pull", pullRef).Run(); err != nil {
		if pullErr := exec.Command("docker", "pull", image).Run(); pullErr != nil {
			return fmt.Errorf("docker pull failed: %w", pullErr)
		}
		pullRef = image
	}

	// Step 2: Get the digest from the pulled image
	digest := getRepoDigest(pullRef)
	var pinned string
	if digest != "" {
		pinned = digest // e.g. nginx@sha256:abc123...
	} else {
		pinned = pullRef // fallback to the pulled reference
	}

	// Step 3: Update compose file with the pinned reference
	composePath := ctx.ComposePath()
	if composePath != "" {
		f, err := compose.Open(composePath)
		if err != nil {
			ctx.Log("fix: cannot open compose file %s: %v", composePath, err)
			return fmt.Errorf("open compose file %s: %w", composePath, err)
		}
		if err := f.Backup(); err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}
		if err := updateImageTagInCompose(f, image, pinned); err != nil {
			return fmt.Errorf("image tag update failed: %w", err)
		}
		if err := f.Save(); err != nil {
			return fmt.Errorf("compose save failed: %w", err)
		}
	}

	return nil
}

func getRepoDigest(image string) string {
	out, err := exec.Command("docker", "inspect", image,
		"--format", "{{range .RepoDigests}}{{.}}{{end}}").Output()
	if err != nil {
		log.Printf("fix: docker inspect for %q failed: %v (falling back to tag pinning)", image, err)
		return ""
	}
	digest := strings.TrimSpace(string(out))
	if strings.Contains(digest, "@sha256:") {
		return digest
	}
	return ""
}

func updateImageTagInCompose(f *compose.File, currentImage, pinned string) error {
	svcs, err := f.ServiceNames()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		img, _ := f.GetFieldRaw(svc, "image")
		if img == currentImage ||
			strings.HasPrefix(img, currentImage+":") ||
			strings.HasPrefix(img, currentImage+"@") {
			if err := f.SetField(svc, "image", pinned); err != nil {
				return fmt.Errorf("update image for service %q: %w", svc, err)
			}
		}
	}
	return nil
}
