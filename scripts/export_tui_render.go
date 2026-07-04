//go:build ignore

// export_tui_render writes the TUI ready-state render for fixture data to stdout.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/tui"
)

type fixtureData struct {
	Hostname string           `json:"hostname"`
	LocalIP  string           `json:"local_ip"`
	Findings []domain.Finding `json:"findings"`
}

func main() {
	fixturePath := "test/e2e/fixtures/mock-snapshot.json"
	if len(os.Args) > 1 {
		fixturePath = os.Args[1]
	}
	data, err := os.ReadFile(fixturePath) //nolint:gosec // local fixture path
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	var fixture fixtureData
	if err := json.Unmarshal(data, &fixture); err != nil {
		fmt.Fprintf(os.Stderr, "parse fixture: %v\n", err)
		os.Exit(1)
	}

	width, height := 140, 44
	if len(os.Args) > 2 {
		if _, err := fmt.Sscanf(os.Args[2], "%d", &width); err != nil {
			fmt.Fprintf(os.Stderr, "width: %v\n", err)
			os.Exit(1)
		}
	}
	if len(os.Args) > 3 {
		if _, err := fmt.Sscanf(os.Args[3], "%d", &height); err != nil {
			fmt.Fprintf(os.Stderr, "height: %v\n", err)
			os.Exit(1)
		}
	}

	reg := fix.New()
	reg.Classify(fixture.Findings)

	live := domain.NewScanProgress(true)
	live.Hostname = fixture.Hostname
	live.LocalIP = fixture.LocalIP
	live.AddFindings(fixture.Findings)
	live.Finalize()

	app := tui.NewReadyApp(live, reg)
	content := tui.RenderScreenshot(app, width, height)
	fmt.Print(content)
}
