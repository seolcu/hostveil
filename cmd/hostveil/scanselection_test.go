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
	if len(opts.Only) != len(model.AllSources())-1 {
		t.Errorf("skip of one domain should select all others, got %v", opts.Only)
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
		t.Error("skipping every domain should be a usage error, not an empty scan")
	}
}

func TestScanSelectionZeroValueIsAFullScan(t *testing.T) {
	opts, msg := scanSelection("", "")
	if msg != "" || opts.Partial() {
		t.Errorf("no flags should mean a full scan, got %+v (%s)", opts, msg)
	}
}
