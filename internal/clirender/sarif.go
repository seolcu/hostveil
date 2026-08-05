package clirender

import (
	"encoding/json"
	"fmt"

	"github.com/seolcu/hostveil/internal/model"
)

// SARIF renders the report as a SARIF 2.1.0 log, the interchange format CI
// systems (GitHub code scanning among them) ingest. The mapping is one run,
// one rule per distinct finding ID, one result per unfixed finding.
//
// Findings have no source-file location in SARIF's sense — they describe a
// host — so results carry a logical location (the service, or "host") and a
// stable partialFingerprint built from Finding.Key(), which is what lets a
// consumer track a finding across scans. Score and per-domain coverage ride
// in the run's properties so a Degraded or Skipped domain survives export:
// a SARIF file with zero results from a scan that could not look is the
// same lie the score model refuses to tell.
func SARIF(r model.Report, version string) (string, error) {
	type text struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		ShortDescription text              `json:"shortDescription"`
		FullDescription  *text             `json:"fullDescription,omitempty"`
		Help             *text             `json:"help,omitempty"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type logicalLocation struct {
		FullyQualifiedName string `json:"fullyQualifiedName"`
	}
	type location struct {
		LogicalLocations []logicalLocation `json:"logicalLocations"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		Level               string            `json:"level"`
		Message             text              `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints"`
	}

	var rules []rule
	ruleIndex := map[string]bool{}
	var results []result
	for _, f := range r.Findings {
		if f.Fixed {
			continue
		}
		if !ruleIndex[f.ID] {
			ruleIndex[f.ID] = true
			ru := rule{
				ID:               f.ID,
				ShortDescription: text{f.Title},
				Properties:       map[string]string{"security-severity": securitySeverity(f.Severity)},
			}
			if f.Description != "" {
				ru.FullDescription = &text{f.Description}
			}
			if f.HowToFix != "" {
				ru.Help = &text{f.HowToFix}
			}
			rules = append(rules, ru)
		}
		where := f.Service
		if where == "" {
			where = "host"
		}
		msg := f.Title
		if f.Service != "" {
			msg = fmt.Sprintf("%s (%s)", f.Title, f.Service)
		}
		results = append(results, result{
			RuleID:    f.ID,
			Level:     sarifLevel(f.Severity),
			Message:   text{msg},
			Locations: []location{{LogicalLocations: []logicalLocation{{FullyQualifiedName: where}}}},
			PartialFingerprints: map[string]string{
				"hostveil/findingKey": f.Key(),
			},
		})
	}
	// A run with no results still must carry a non-null, empty array —
	// `"results": null` is invalid SARIF and some ingesters reject it.
	if results == nil {
		results = []result{}
	}
	if rules == nil {
		rules = []rule{}
	}

	domains := map[string]any{}
	for _, d := range r.Domains {
		domains[d.Source.String()] = map[string]any{
			"state":  d.State.String(),
			"reason": d.Reason,
		}
	}
	axes := map[string]any{}
	for _, ax := range r.Score.Axes {
		axes[ax.ID] = map[string]any{
			"score":      ax.Score,
			"applicable": ax.Applicable,
			"degraded":   ax.Degraded,
		}
	}

	log := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "hostveil",
					"version":        version,
					"informationUri": "https://github.com/seolcu/hostveil",
					"rules":          rules,
				},
			},
			"results": results,
			"properties": map[string]any{
				"score":           r.Score.Overall,
				"scoreApplicable": r.Score.Applicable,
				"axes":            axes,
				"domains":         domains,
			},
		}},
	}
	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// sarifLevel maps severities onto SARIF's three levels.
//
// The mapping is one-to-one, which it was not before: Critical and High both
// became "error", so SARIF was already saying what the three-level scale now
// says. Nothing an ingesting tool sees changed when the scale did.
func sarifLevel(s model.Severity) string {
	switch s {
	case model.SeverityExposed:
		return "error"
	case model.SeverityWeak:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the 0–10 scale GitHub code scanning ranks by, which
// buckets at 9.0 (critical), 7.0 (high) and 4.0 (medium).
//
// Exposed lands in "critical" rather than straddling it and "high" as the two
// levels it replaces did: it is the level that says the problem is reachable
// now, and code scanning's own critical band is the one that means act today.
func securitySeverity(s model.Severity) string {
	switch s {
	case model.SeverityExposed:
		return "9.5"
	case model.SeverityWeak:
		return "5.5"
	default:
		return "3.0"
	}
}
