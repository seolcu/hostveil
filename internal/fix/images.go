package fix

import (
	"fmt"
	"os/exec"

	"github.com/seolcu/hostveil/internal/compose"
)

func registerImageFixes(r *Registry) {
	r.Register(&Fix{
		FindingID: "trivy.cve-*",
		Label:     "Update image to patched version",
		Warning:   "Updating the image may break API compatibility. Verify after applying.",
		Actions: []Action{
			{
				Type:  ActionEdit,
				Label: "Update image tag and pull",
				Apply: func(ctx Context) error {
					return fixImageCVE(ctx)
				},
			},
		},
	})
	r.Register(&Fix{
		FindingID: "trivy.cve-*-base",
		Label:     "Switch to a different base image",
		Actions:   []Action{{Type: ActionPrompt, Label: "Manually change base image", Description: "Edit the Dockerfile FROM line to use a less vulnerable base image."}},
	})
}

func fixImageCVE(ctx Context) error {
	ev := ctx.Finding.Evidence
	image := ctx.Finding.Service // holds the image name for CVE findings
	if image == "" {
		return fmt.Errorf("no image name in finding")
	}
	fixedVer := ev["fixed_version"]
	pkgName := ev["package"]
	if fixedVer == "" {
		return fmt.Errorf("no fixed version available")
	}

	// Try to find and update the image in compose files
	composePath := ctx.ComposePath()
	var f *compose.File
	if composePath != "" {
		var err error
		f, err = compose.Open(composePath)
		if err == nil {
			f.Backup()
			_ = updateImageTagInCompose(f, image, fixedVer, pkgName)
			_ = f.Save()
		}
	}

	// Pull the latest patched image
	return exec.Command("docker", "pull", image).Run()
}

func updateImageTagInCompose(f *compose.File, currentImage, fixedVersion, pkgName string) error {
	svcs, err := f.ServiceNames()
	if err != nil {
		return err
	}
	for _, svc := range svcs {
		img, _ := f.GetFieldRaw(svc, "image")
		if img == currentImage || img == currentImage+":latest" {
			pinned := fmt.Sprintf("%s@%s", currentImage, fixedVersion)
			f.SetField(svc, "image", pinned)
		}
	}
	return nil
}
