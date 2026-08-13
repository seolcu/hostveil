package compose

import (
	"context"
	"errors"
	"testing"

	"github.com/seolcu/hostveil/internal/check/checktest"
)

const hcFormat = "{{if .Config.Healthcheck}}{{if .Config.Healthcheck.Test}}yes{{end}}{{end}}"

// The image is the other place a healthcheck comes from, and ds012 read only
// the compose file. On a real host this produced the finding "No healthcheck
// defined" against a container `docker ps` was reporting as `healthy`, because
// the image declared `HEALTHCHECK` in its own Dockerfile and Docker was
// running it.
func TestAnImagesOwnHealthcheckCountsAsOne(t *testing.T) {
	argv := func(img string) []string {
		return []string{"docker", "image", "inspect", "--format", hcFormat, img}
	}
	ctx := context.Background()

	t.Run("the image declares one", func(t *testing.T) {
		r := checktest.New().Script("yes\n", argv("itzg/minecraft-server:java25")...)
		if !imageDeclaresHealthcheck(ctx, r, "itzg/minecraft-server:java25") {
			t.Error("an image with a HEALTHCHECK was read as having none")
		}
	})

	t.Run("the image declares none", func(t *testing.T) {
		r := checktest.New().Script("\n", argv("lscr.io/linuxserver/jellyfin:latest")...)
		if imageDeclaresHealthcheck(ctx, r, "lscr.io/linuxserver/jellyfin:latest") {
			t.Error("an image with no HEALTHCHECK was read as having one")
		}
	})

	// Not pulled, daemon refusing, image removed since the compose file was
	// written. Of the two ways to be wrong, keeping the finding is the one
	// that does not hide a missing healthcheck.
	t.Run("the image cannot be inspected", func(t *testing.T) {
		r := checktest.New().Fail(errors.New("no such image"), argv("ghcr.io/absent:1")...)
		if imageDeclaresHealthcheck(ctx, r, "ghcr.io/absent:1") {
			t.Error("an image that could not be inspected was read as declaring a healthcheck")
		}
	})

	// A service with no image at all (build: only) has nothing to ask about.
	t.Run("no image named", func(t *testing.T) {
		if imageDeclaresHealthcheck(ctx, checktest.New(), "  ") {
			t.Error("an empty image name produced an answer")
		}
	})

	// The format string prints one token on purpose. A daemon answering
	// something else is a miss, not a match — searching a whole inspect
	// document for the word would call it present on any image mentioning it.
	t.Run("an unexpected answer is a miss", func(t *testing.T) {
		r := checktest.New().Script("{\"Config\":{\"Healthcheck\":null}}\n", argv("weird:1")...)
		if imageDeclaresHealthcheck(ctx, r, "weird:1") {
			t.Error("an unparsed answer was read as a healthcheck")
		}
	})
}
