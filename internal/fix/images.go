package fix

import (
	"fmt"
	"strings"

	"github.com/seolcu/hostveil/internal/compose"
	"github.com/seolcu/hostveil/internal/domain"
)

func registerImageFixes(r *Registry) {
	r.Register(&Fix{
		FindingID: "trivy.cve-*",
		Label:     "Update image tag or rebuild with patched base/package version. Verify with a new Trivy scan.",
		Kind:      domain.RemediationManual,
		Actions:   nil,
	})
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
