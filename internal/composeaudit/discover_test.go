package composeaudit

import (
	"encoding/json"
	"os/exec"
	"testing"
)

type fakeRunner struct {
	output []byte
}

func (f fakeRunner) Output(cmd *exec.Cmd) ([]byte, error) {
	return f.output, nil
}

func (f fakeRunner) Run(cmd *exec.Cmd) error {
	return nil
}

func TestDiscoverProjects_MultiFile(t *testing.T) {
	raw := []composeLSProject{{
		Name:        "demo",
		ConfigFiles: "/srv/demo/compose.yaml,/srv/demo/compose.override.yaml",
	}}
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	projects, err := DiscoverProjects(fakeRunner{output: out})
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
	if len(projects[0].ComposePaths) != 2 {
		t.Fatalf("expected 2 compose paths, got %v", projects[0].ComposePaths)
	}
	if projects[0].ComposePath != "/srv/demo/compose.yaml" {
		t.Errorf("ComposePath = %q", projects[0].ComposePath)
	}
}
