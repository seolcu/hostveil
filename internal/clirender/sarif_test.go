package clirender

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func sarifOf(t *testing.T, r model.Report) map[string]any {
	t.Helper()
	out, err := SARIF(r, "v-test")
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	return log
}

func sarifRun(t *testing.T, log map[string]any) map[string]any {
	t.Helper()
	runs, ok := log["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("want exactly one run, got %v", log["runs"])
	}
	return runs[0].(map[string]any)
}

func TestSARIFMapsFindingsToResultsAndRules(t *testing.T) {
	f1 := model.NewFinding("ssh.rootlogin", "Root login allowed", model.SeverityHigh,
		model.SourceSSH, model.RemediationReview,
		model.WithDescription("desc"), model.WithHowToFix("how"))
	f2 := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityCritical,
		model.SourceCompose, model.RemediationAuto, model.WithService("cache"))
	f3 := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityCritical,
		model.SourceCompose, model.RemediationAuto, model.WithService("db"))
	fixed := model.NewFinding("ssh.x11forwarding", "X11 on", model.SeverityLow,
		model.SourceSSH, model.RemediationAuto)
	fixed.Fixed = true

	report := model.Report{Findings: []model.Finding{f1, f2, f3, fixed}}
	run := sarifRun(t, sarifOf(t, report))

	results := run["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("want 3 results (fixed finding excluded), got %d", len(results))
	}
	first := results[0].(map[string]any)
	if first["ruleId"] != "ssh.rootlogin" || first["level"] != "error" {
		t.Errorf("first result = %v, want ssh.rootlogin at error", first)
	}
	fp := first["partialFingerprints"].(map[string]any)
	if fp["hostveil/findingKey"] != f1.Key() {
		t.Errorf("fingerprint = %v, want %s", fp, f1.Key())
	}

	// One rule per distinct ID, even with two ds018 results.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("want 2 rules for 2 distinct IDs, got %d", len(rules))
	}
	if driver["version"] != "v-test" {
		t.Errorf("driver version = %v", driver["version"])
	}

	// Same-ID results stay distinguishable through the logical location.
	second := results[1].(map[string]any)
	loc := second["locations"].([]any)[0].(map[string]any)["logicalLocations"].([]any)[0].(map[string]any)
	if loc["fullyQualifiedName"] != "cache" {
		t.Errorf("logical location = %v, want the service name", loc)
	}
}

func TestSARIFSeverityLevels(t *testing.T) {
	cases := map[model.Severity]string{
		model.SeverityCritical: "error",
		model.SeverityHigh:     "error",
		model.SeverityMedium:   "warning",
		model.SeverityLow:      "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%v) = %q, want %q", sev, got, want)
		}
	}
}

// An empty scan must produce `"results": []`, not `"results": null` —
// null is invalid SARIF and some ingesters reject the whole file.
func TestSARIFEmptyReportHasEmptyArrays(t *testing.T) {
	out, err := SARIF(model.Report{}, "v-test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"results": null`) || strings.Contains(out, `"rules": null`) {
		t.Errorf("null arrays in empty SARIF output:\n%s", out)
	}
}

// Degradation must survive export: a SARIF file with zero results from a
// scan that could not look would otherwise read as a clean host.
func TestSARIFCarriesDomainCoverage(t *testing.T) {
	report := model.Report{
		Domains: []model.DomainResult{
			{Source: model.SourceCVE, State: model.ScanSkipped, Reason: "trivy not installed"},
		},
	}
	run := sarifRun(t, sarifOf(t, report))
	props := run["properties"].(map[string]any)
	domains := props["domains"].(map[string]any)
	cve := domains["cve"].(map[string]any)
	if cve["reason"] != "trivy not installed" {
		t.Errorf("domain coverage lost in export: %v", cve)
	}
	if _, ok := props["scoreApplicable"]; !ok {
		t.Error("scoreApplicable missing from run properties")
	}
}
