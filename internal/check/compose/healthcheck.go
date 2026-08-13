package compose

import (
	"context"
	"strings"

	"github.com/seolcu/hostveil/internal/platform"
)

// imageDeclaresHealthcheck reports whether the image itself defines a
// HEALTHCHECK, which Docker runs when the compose file names none.
//
// ds012 asks a question about the container — its description says a failed
// service can appear healthy while it is actually down — and answers it from
// the compose file alone. That is not the same question. An image with
// `HEALTHCHECK` in its Dockerfile gets one whether or not the compose file
// repeats it, so a service running such an image was told to add a healthcheck
// it already had, while `docker ps` showed the container as `healthy` beside
// the finding saying it had none. The runtime half of this domain never had
// the bug: `docker inspect` reports the effective configuration, so it sees
// the image's own.
//
// A miss keeps the finding. "I could not inspect the image" is not "the image
// declares nothing", and of the two ways to be wrong here, reporting a
// healthcheck that is already there costs the operator a moment and hiding a
// missing one costs them the thing the check is for.
func imageDeclaresHealthcheck(ctx context.Context, r platform.CommandRunner, image string) bool {
	if strings.TrimSpace(image) == "" {
		return false
	}
	// The format prints exactly one token so a daemon that answers something
	// unexpected is a miss rather than a match. Asking for the whole struct
	// and searching it would call a healthcheck present on any image whose
	// metadata happens to contain the word.
	out, err := r.Run(ctx, "docker", "image", "inspect",
		"--format", "{{if .Config.Healthcheck}}{{if .Config.Healthcheck.Test}}yes{{end}}{{end}}", image)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}
