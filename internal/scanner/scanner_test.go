package scanner

import (
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestScanWithComposeFile(t *testing.T) {
	result, err := Run(Config{
		ComposeFiles: []string{"../../tests/scenarios/vaultwarden-domain/docker-compose.yml"},
		UserMode:     true,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.TotalFindings() == 0 {
		t.Error("expected at least 1 finding from vaultwarden scan")
	}

	if result.ScoreReport.Overall > 100 {
		t.Errorf("overall score should be <= 100, got %d", result.ScoreReport.Overall)
	}

	if result.Metadata.ComposeFile == "" {
		t.Error("expected compose file path in metadata")
	}
}

func TestScanWithEmptyConfig(t *testing.T) {
	result, err := Run(Config{UserMode: true})
	if err != nil {
		t.Fatalf("Run failed with empty config: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestScanFindsExposureFinding(t *testing.T) {
	result, err := Run(Config{
		ComposeFiles: []string{"../../tests/scenarios/vaultwarden-domain/docker-compose.yml"},
		UserMode:     true,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	hasExposure := false
	for _, f := range result.Findings {
		if f.ID == "exposure.public_binding" {
			hasExposure = true
			break
		}
	}

	if !hasExposure {
		t.Error("expected exposure.public_binding finding")
	}
}

func TestScoreCalculation(t *testing.T) {
	result, err := Run(Config{
		ComposeFiles: []string{"../../tests/scenarios/vaultwarden-domain/docker-compose.yml"},
		UserMode:     true,
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	for _, axis := range allAxes() {
		_, ok := result.ScoreReport.AxisScores[axis]
		if !ok {
			t.Errorf("missing axis score for %v", axis)
		}
	}
}

func allAxes() []domain.Axis {
	return []domain.Axis{domain.AxisSensitiveData, domain.AxisExcessivePermissions, domain.AxisUnnecessaryExposure, domain.AxisUpdateSupplyChain, domain.AxisHostHardening}
}
