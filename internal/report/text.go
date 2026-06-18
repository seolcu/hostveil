// Package report renders a scan result to stdout (text) and to a
// file (text + JSON sibling). The two surfaces are produced from the
// same in-memory representation; the text renderer is a strict
// projection of the JSON contract.
package report

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/version"
)

// TextOptions tunes the text renderer.
type TextOptions struct {
	Width     int
	NoColor   bool
}

// WriteText writes the human-readable text report to w.
func WriteText(w io.Writer, r Run, opt TextOptions) {
	width := opt.Width
	if width <= 0 {
		width = 100
	}
	fmt.Fprintf(w, "%s v%s (commit %s, built %s)\n",
		r.HostveilVersion, schemaVersionOrVersion(r.SchemaVersion), r.HostveilCommit, r.HostveilBuiltAt)
	fmt.Fprintf(w, "Host:     %s (%s %s, %s)\n", r.Host.Hostname, r.Host.OSFamily, r.Host.OSVersion, r.Host.Arch)
	if r.ScanRun.FinishedAt != nil {
		fmt.Fprintf(w, "Scan:     %s → %s (%s)\n",
			r.ScanRun.StartedAt.Format(time.RFC3339),
			r.ScanRun.FinishedAt.Format(time.RFC3339),
			r.ScanRun.FinishedAt.Sub(r.ScanRun.StartedAt).Round(time.Second))
	}
	fmt.Fprintf(w, "Status:   %s\n", r.ScanRun.Status)
	fmt.Fprintf(w, "Report:   %s\n", r.ScanRun.ReportPath)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Summary")
	fmt.Fprintln(w, "-------")
	fmt.Fprintf(w, "  critical: %d\n", r.ScanRun.FindingCountCritical)
	fmt.Fprintf(w, "  high:     %d\n", r.ScanRun.FindingCountHigh)
	fmt.Fprintf(w, "  medium:   %d\n", r.ScanRun.FindingCountMedium)
	fmt.Fprintf(w, "  low:      %d\n", r.ScanRun.FindingCountLow)
	fmt.Fprintf(w, "  total:    %d\n", totalFindings(r))
	counts := classifyCounts(r.Findings)
	fmt.Fprintf(w, "  new since last run:        %d\n", counts["new"])
	fmt.Fprintf(w, "  still present:             %d\n", counts["still_present"])
	fmt.Fprintf(w, "  resolved since last run:   %d\n", counts["resolved"])
	fmt.Fprintf(w, "  suppressed:                %d\n", counts["suppressed"])
	fmt.Fprintln(w)

	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "Findings")
		fmt.Fprintln(w, "--------")
		writeGrouped(w, r.Findings, width)
	}

	if len(r.ScanRun.CategoriesSkipped) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Skipped categories")
		fmt.Fprintln(w, "------------------")
		for _, s := range r.ScanRun.CategoriesSkipped {
			fmt.Fprintf(w, "  %-26s  (%s: %s)\n", s.Category, s.Reason, s.Detail)
		}
	}
}

// writeGrouped writes the findings grouped by category, ordered by
// severity within each category. Matches contracts/report.md.
func writeGrouped(w io.Writer, findings []model.Finding, _ int) {
	byCat := map[model.Category][]model.Finding{}
	order := []model.Category{}
	for _, f := range findings {
		if _, ok := byCat[f.Category]; !ok {
			order = append(order, f.Category)
		}
		byCat[f.Category] = append(byCat[f.Category], f)
	}
	for _, c := range order {
		fmt.Fprintf(w, "[%s]\n", categoryTitle(c))
		fs := byCat[c]
		sort.Slice(fs, func(i, j int) bool {
			if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
				return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
			}
			return fs[i].RuleID < fs[j].RuleID
		})
		for _, f := range fs {
			fmt.Fprintf(w, "  [%s] [%s] %s\n", f.Severity, f.State, f.Title)
			if loc := primaryLocation(f); loc != "" {
				fmt.Fprintf(w, "      %s\n", loc)
			}
			fmt.Fprintf(w, "      What: %s\n", wrap(f.Description, "            "))
			fmt.Fprintln(w)
		}
	}
}

func primaryLocation(f model.Finding) string {
	if len(f.EntityRefs) == 0 {
		return ""
	}
	r := f.EntityRefs[0]
	switch r.Kind {
	case model.EntityRefKindConfigFile, model.EntityRefKindSetting:
		return r.Display
	}
	return r.Display
}

func categoryTitle(c model.Category) string {
	switch c {
	case model.CategorySSH:
		return "SSH"
	case model.CategoryDocker:
		return "Docker"
	case model.CategoryImageCVE:
		return "Image CVEs"
	case model.CategoryReverseProxy:
		return "Reverse Proxy"
	case model.CategorySSLTLS:
		return "SSL/TLS"
	case model.CategoryHardeningFirewall:
		return "Hardening — Firewall"
	case model.CategoryHardeningFail2ban:
		return "Hardening — Fail2ban"
	case model.CategoryHardeningUnattended:
		return "Hardening — Unattended Upgrades"
	case model.CategoryHardeningSysctl:
		return "Hardening — Sysctl"
	case model.CategoryHardeningUpdates:
		return "Hardening — Pending Updates"
	}
	return string(c)
}

func classifyCounts(fs []model.Finding) map[string]int {
	out := map[string]int{"new": 0, "still_present": 0, "resolved": 0, "suppressed": 0}
	for _, f := range fs {
		out[string(f.State)]++
	}
	return out
}

func totalFindings(r Run) int {
	return r.ScanRun.FindingCountCritical + r.ScanRun.FindingCountHigh + r.ScanRun.FindingCountMedium + r.ScanRun.FindingCountLow
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	}
	return 0
}

// wrap is a minimal word-wrap. For v3.0.0 we don't try to be clever
// about leading whitespace; the reader gets one paragraph with the
// given prefix.
func wrap(s, prefix string) string {
	if s == "" {
		return ""
	}
	return strings.TrimSpace(prefix+strings.ReplaceAll(s, "\n", "\n"+prefix))
}

// Sink writes the report to stdout and (unless NoFile is true) to a
// timestamped file under reportDir. The file path is written back
// into the ScanRun row by the caller via the returned value.
type Sink struct {
	ReportDir string
	NoFile    bool
}

// Write writes the text and JSON forms of r to stdout and to a file.
// On success it returns the on-disk path (or "" if NoFile is true).
func (s Sink) Write(r Run) (string, error) {
	if err := ensureDir(s.ReportDir); err != nil {
		return "", err
	}
	WriteText(stdout(), r, TextOptions{Width: 100})
	if s.NoFile {
		return "", nil
	}
	ts := r.ScanRun.StartedAt.UTC().Format("20060102-150405")
	textPath := filepath.Join(s.ReportDir, "hostveil-"+ts+".txt")
	jsonPath := filepath.Join(s.ReportDir, "hostveil-"+ts+".json")
	if err := writeFile(textPath, func(w io.Writer) error {
		WriteText(w, r, TextOptions{Width: 100})
		return nil
	}); err != nil {
		return "", err
	}
	if err := writeFile(jsonPath, func(w io.Writer) error {
		return WriteJSON(w, r)
	}); err != nil {
		return "", err
	}
	return textPath, nil
}

// BuildRunFromScanRun composes a Run from a ScanRun, its findings,
// and the host row. The host is fetched in the report layer (it's
// already in the ScanRun.HostID foreign key).
func BuildRunFromScanRun(sr model.ScanRun, findings []model.Finding, host model.Host) Run {
	return Run{
		SchemaVersion:   "1.0.0",
		HostveilVersion: version.Version,
		HostveilCommit:  version.Commit,
		HostveilBuiltAt: version.Built,
		ScanRun:         sr,
		Host:            host,
		Findings:        findings,
	}
}

// schemaVersionOrVersion returns s if non-empty, else falls back to
// the binary's version constant. Used in the report header.
func schemaVersionOrVersion(s string) string {
	if s != "" {
		return s
	}
	return version.Version
}
