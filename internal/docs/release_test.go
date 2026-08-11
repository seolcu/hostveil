package docs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CI compiles every release target on the pull request so that a break is
// caught there rather than during a release, where it demotes the release to a
// draft. The step's own comment says so. What it cannot say is which targets
// those are: the list is written out in the workflow, and the set it is meant
// to mirror lives in .goreleaser.yaml.
//
// Add an architecture to the release build and nothing complains. CI keeps
// compiling the three it has always compiled, goreleaser starts building four,
// and the first compile of the new one happens during a release — which is the
// exact failure this step was added to prevent, reintroduced by the step going
// stale rather than by anyone removing it.
//
// linux/amd64 is deliberately absent from the workflow's loop: the ordinary
// Build step is that target, so it is added back here rather than compiled
// twice there.
const ciNativeTarget = "linux/amd64"

var ciCrossCompileLoop = regexp.MustCompile(`for target in ([^;]+);`)

type goreleaserConfig struct {
	Builds []struct {
		GOOS   []string `yaml:"goos"`
		GOARCH []string `yaml:"goarch"`
		Ignore []struct {
			GOOS   string `yaml:"goos"`
			GOARCH string `yaml:"goarch"`
		} `yaml:"ignore"`
	} `yaml:"builds"`
}

func TestCICompilesEveryTargetGoreleaserBuilds(t *testing.T) {
	var cfg goreleaserConfig
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".goreleaser.yaml")), &cfg); err != nil {
		t.Fatalf("parsing .goreleaser.yaml: %v", err)
	}
	if len(cfg.Builds) == 0 {
		t.Fatal(".goreleaser.yaml declares no builds; either the file moved or its " +
			"shape changed, and this pin is comparing against nothing")
	}

	var released []string
	for _, b := range cfg.Builds {
		for _, os := range b.GOOS {
			for _, arch := range b.GOARCH {
				if slices.ContainsFunc(b.Ignore, func(ig struct {
					GOOS   string `yaml:"goos"`
					GOARCH string `yaml:"goarch"`
				}) bool {
					return ig.GOOS == os && ig.GOARCH == arch
				}) {
					continue
				}
				released = append(released, fmt.Sprintf("%s/%s", os, arch))
			}
		}
	}
	if len(released) == 0 {
		t.Fatal(".goreleaser.yaml produced no goos/goarch pairs")
	}

	ci := readRepoFile(t, filepath.Join(".github", "workflows", "ci.yml"))
	m := ciCrossCompileLoop.FindStringSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml no longer has a `for target in …;` cross-compile loop; " +
			"if the step was rewritten, rewrite this pin with it")
	}
	compiled := append(strings.Fields(m[1]), ciNativeTarget)

	slices.Sort(released)
	released = slices.Compact(released)
	slices.Sort(compiled)
	compiled = slices.Compact(compiled)

	for _, target := range released {
		if !slices.Contains(compiled, target) {
			t.Errorf("goreleaser builds %s for the release and CI never compiles it; "+
				"add it to the cross-compile loop in .github/workflows/ci.yml "+
				"(CI compiles %v, the release needs %v)", target, compiled, released)
		}
	}
	for _, target := range compiled {
		if !slices.Contains(released, target) {
			t.Errorf("CI compiles %s, which no release ships; the loop in ci.yml "+
				"is spending gate time on a target nobody downloads", target)
		}
	}
}

// The native target is the one claim above that the workflow does not spell
// out, so it is checked rather than assumed: if the Build step stops being
// linux/amd64, adding it back to the compiled set silently hides a real gap.
func TestTheGateBuildsOnTheTargetItAssumes(t *testing.T) {
	ci := readRepoFile(t, filepath.Join(".github", "workflows", "ci.yml"))
	if !strings.Contains(ci, "runs-on: ubuntu-latest") {
		t.Errorf("ci.yml's build job no longer runs on ubuntu-latest, so %q is no "+
			"longer the target its plain `go build` covers", ciNativeTarget)
	}
}
