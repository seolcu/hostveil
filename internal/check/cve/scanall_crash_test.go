package cve

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// panicOnImage is a platform.CommandRunner whose Run panics for one named
// image and behaves like an ordinary failing run otherwise (never "no
// findings" — that would make the panicking path indistinguishable from a
// clean scan of the other target).
type panicOnImage struct{ image string }

func (r panicOnImage) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	for _, a := range args {
		if a == r.image {
			panic("a parser bug reading trivy's output for " + a)
		}
	}
	return nil, errTrivyStub
}

func (r panicOnImage) LookPath(string) (string, error) { return "/usr/bin/trivy", nil }

var errTrivyStub = errors.New("stub trivy failure")

// scanAll runs each target's scan in its own goroutine once there is more
// than one, and check.runOne's recover — the one every other domain relies
// on — does not reach a goroutine scanAll spawns itself. Before scanAll grew
// its own recover, a bug in one image's scan (or its JSON parsing) took the
// whole process down instead of degrading to a per-image failure the way
// Trivy erroring on that image already does.
func TestAPanicScanningOneImageDoesNotTakeTheProcessWithIt(t *testing.T) {
	targets := []target{
		{image: "bad:latest", standalone: true},
		{image: "trivy-unreachable:latest", standalone: true},
	}
	r := panicOnImage{image: "bad:latest"}

	findings, failed, firstErr := scanAll(context.Background(), r, targets)

	if len(findings) != 0 {
		t.Errorf("got %d findings from two failing targets, want 0", len(findings))
	}
	if failed != 2 {
		t.Errorf("got failed=%d, want 2 (both targets errored, one by panic)", failed)
	}
	if firstErr == nil {
		t.Fatal("scanAll returned no error at all for two failing targets")
	}
}

// The recovered error names the image, the same way an ordinary Trivy
// failure does, so a Reason string does not read as "nothing was examined."
func TestAPanicScanningOneImageIsReportedByName(t *testing.T) {
	targets := []target{{image: "bad:latest", standalone: true}}
	r := panicOnImage{image: "bad:latest"}

	_, failed, firstErr := scanAll(context.Background(), r, targets)
	if failed != 1 || firstErr == nil {
		t.Fatalf("got failed=%d err=%v, want one failure naming the image", failed, firstErr)
	}
	if !strings.Contains(firstErr.Error(), "bad:latest") {
		t.Errorf("the recovered error does not name the image that panicked: %v", firstErr)
	}
}
