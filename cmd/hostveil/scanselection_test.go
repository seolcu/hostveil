package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/model"
)

func TestScanSelectionOnly(t *testing.T) {
	opts, msg := scanSelection("ssh,firewall", "")
	if msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if !opts.Partial() || len(opts.Only) != 2 ||
		!slices.Contains(opts.Only, model.SourceSSH) || !slices.Contains(opts.Only, model.SourceFirewall) {
		t.Errorf("opts = %+v, want ssh+firewall", opts)
	}
}

func TestScanSelectionSkipIsTheComplement(t *testing.T) {
	opts, msg := scanSelection("", "cve")
	if msg != "" {
		t.Fatalf("unexpected error: %s", msg)
	}
	if len(opts.Only) != len(model.AllSources())-len(model.OptInSources())-1 {
		t.Errorf("skip of one domain should select every other default domain, got %v", opts.Only)
	}
	if slices.Contains(opts.Only, model.SourceCVE) {
		t.Error("the skipped domain must not be selected")
	}
}

func TestScanSelectionErrors(t *testing.T) {
	if _, msg := scanSelection("ssh", "cve"); msg == "" {
		t.Error("--only and --skip together should be a usage error")
	}
	if _, msg := scanSelection("bogus", ""); msg == "" || !strings.Contains(msg, "bogus") || !strings.Contains(msg, "ssh") {
		t.Errorf("an unknown domain should be named alongside the valid ones, got %q", msg)
	}

	var names []string
	for _, s := range model.AllSources() {
		names = append(names, s.String())
	}
	if _, msg := scanSelection("", strings.Join(names, ",")); msg == "" {
		t.Error("skipping every domain should be a usage error")
	}
}

func TestScanSelectionZeroValueIsAFullScan(t *testing.T) {
	opts, msg := scanSelection("", "")
	if msg != "" || opts.Partial() {
		t.Errorf("no flags should mean a full scan, got %+v (%s)", opts, msg)
	}
}

// --skip is "a full scan minus these", and a full scan leaves out the opt-in
// domains --with did not name. Selecting them anyway would make
// `scan --skip cve` the one way to get the forensic findings without asking.
func TestScanSelectionSkipLeavesOptInOutUnlessNamed(t *testing.T) {
	t.Cleanup(func() { withDomains = nil })
	withDomains = nil
	opts, _ := scanSelection("", "cve")
	if slices.Contains(opts.Only, model.SourceForensic) {
		t.Errorf("--skip without --with selected an opt-in domain: %v", opts.Only)
	}
	withDomains = []model.Source{model.SourceForensic}
	opts, _ = scanSelection("", "cve")
	if !slices.Contains(opts.Only, model.SourceForensic) {
		t.Errorf("--skip with --with forensic left forensic out: %v", opts.Only)
	}
}

func TestParseOptIn(t *testing.T) {
	got, err := parseOptIn(" forensic ")
	if err != nil || len(got) != 1 || got[0] != model.SourceForensic {
		t.Errorf("parseOptIn(forensic) = %v, %v", got, err)
	}
	if _, err := parseOptIn("ssh"); err == nil || !strings.Contains(err.Error(), "forensic") {
		t.Errorf("a default domain should be refused and the opt-in ones named, got %v", err)
	}
	if _, err := parseOptIn(","); err == nil {
		t.Error("an empty list should be refused")
	}
}
