package export

import (
	"encoding/json"
	"fmt"

	"github.com/seolcu/hostveil/internal/domain"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool     sarifTool      `json:"tool"`
	Results  []sarifResult  `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string              `json:"name"`
	SemanticVersion string             `json:"semanticVersion"`
	Rules          []sarifRule         `json:"rules"`
}

type sarifRule struct {
	ID              string          `json:"id"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	FullDescription  sarifMessage   `json:"fullDescription"`
	Properties      sarifProperties `json:"properties"`
}

type sarifProperties struct {
	Severity string `json:"security-severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Message   sarifMessage    `json:"message"`
	Level     string          `json:"level"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func SARIF(r *domain.ScanResult) (string, error) {
	var rules []sarifRule
	var results []sarifResult

	seen := make(map[string]bool)
	for _, f := range r.Findings {
		if !seen[f.ID] {
			seen[f.ID] = true
			rules = append(rules, sarifRule{
				ID: f.ID,
				ShortDescription: sarifMessage{Text: f.Title},
				FullDescription:  sarifMessage{Text: f.Description},
				Properties:      sarifProperties{Severity: f.Severity.String()},
			})
		}

		level := "error"
		switch f.Severity {
		case domain.SeverityLow:
			level = "note"
		case domain.SeverityMedium:
			level = "warning"
		}

		results = append(results, sarifResult{
			RuleID:  f.ID,
			Message: sarifMessage{Text: f.Title + ": " + f.Description},
			Level:   level,
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: fmt.Sprintf("file://%s/docker-compose.yml", f.Service),
						},
					},
				},
			},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "hostveil",
						SemanticVersion: "1.0.0",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
