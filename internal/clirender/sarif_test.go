package clirender

import (
	"encoding/json"
	"strconv"
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
	f2 := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityHigh,
		model.SourceCompose, model.RemediationAuto, model.WithService("cache"))
	f3 := model.NewFinding("compose.ds018", "Datastore exposed", model.SeverityHigh,
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
		model.SeverityHigh:   "error",
		model.SeverityMedium: "warning",
		model.SeverityLow:    "note",
	}
	// One arm per level, and every level covered: SARIF's three and hostveil's
	// three now line up exactly, which is what a missing arm would hide.
	if len(cases) != len(model.AllSeverities()) {
		t.Fatalf("%d severities, %d mapped to SARIF levels", len(model.AllSeverities()), len(cases))
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

// TestSARIFLevelsStillMeanWhatTheyMeant is the same compatibility claim the
// exit code makes, for the export CI systems and GitHub code scanning read.
//
// Critical and High both mapped to "error" before they became one level, so
// SARIF was already saying what the three-level scale says. An ingester's
// alerts must not move because hostveil renamed something.
//
// Written against the old ordinals rather than the old constants, which no
// longer exist: the numbers are what a snapshot on disk holds, and reading
// one back is the only way left to name a level this build never had.
func TestSARIFLevelsStillMeanWhatTheyMeant(t *testing.T) {
	for _, tc := range []struct {
		ordinal int
		was     string
		level   string
	}{
		{0, "critical", "error"},
		{1, "high", "error"},
		{2, "medium", "warning"},
		{3, "low", "note"},
	} {
		var sev model.Severity
		if err := json.Unmarshal([]byte(strconv.Itoa(tc.ordinal)), &sev); err != nil {
			t.Fatalf("%s (%d) no longer reads at all: %v", tc.was, tc.ordinal, err)
		}
		if got := sarifLevel(sev); got != tc.level {
			t.Errorf("a finding that was %s exports as %q, and used to export as %q",
				tc.was, got, tc.level)
		}
	}
}

// TestEverySeverityCarriesASecurityScore is the other half of the SARIF
// contract, and until now it had none.
//
// security-severity is what GitHub code scanning ranks and filters by, and
// it is the only number in the export. Replacing the whole of
// securitySeverity with a constant passed every test in the repository —
// so a rename, a reordering, or a level added without a case would have
// shipped a SARIF file where nothing sorts.
//
// It asserts the property rather than three literals: each level's score is
// well-formed, inside the scale, and strictly greater than the level below
// it. Pinning the exact numbers would fail the day somebody deliberately
// retunes them, which is a choice rather than a defect; ordering is not.
func TestEverySeverityCarriesASecurityScore(t *testing.T) {
	prev := 11.0
	for _, sev := range model.AllSeverities() {
		raw := securitySeverity(sev)
		got, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			t.Errorf("%s exports security-severity %q, which is not a number", sev, raw)
			continue
		}
		if got < 0 || got > 10 {
			t.Errorf("%s exports security-severity %v, outside code scanning's 0–10 scale", sev, got)
		}
		if got >= prev {
			t.Errorf("%s exports security-severity %v, which does not rank below the level above it (%v) — "+
				"code scanning sorts by this number, so an order that does not descend is an export "+
				"that cannot be triaged", sev, got, prev)
		}
		prev = got
	}
}

// And the top level has to land in the band that means act today. The
// mapping from three levels onto code scanning's four bands is a judgement
// (see securitySeverity's comment) and this is the part of it that is not
// negotiable: a finding reachable right now must not arrive as "high".
func TestTheTopSeverityLandsInTheCriticalBand(t *testing.T) {
	const criticalBand = 9.0
	top := model.AllSeverities()[0]
	got, err := strconv.ParseFloat(securitySeverity(top), 64)
	if err != nil {
		t.Fatalf("%s exports a security-severity that is not a number: %v", top, err)
	}
	if got < criticalBand {
		t.Errorf("%s exports security-severity %v, below code scanning's critical band (%v)",
			top, got, criticalBand)
	}
}
