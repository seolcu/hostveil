package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/seolcu/hostveil/internal/log"
	"github.com/seolcu/hostveil/internal/model"
	"github.com/seolcu/hostveil/internal/report"
	"github.com/seolcu/hostveil/internal/scan"
	"github.com/seolcu/hostveil/internal/store"
)

var (
	scanFlagCategories string
	scanFlagRefreshCVE bool
	scanFlagCVESource  string
	scanFlagReportDir  string
	scanFlagNoFile     bool
)

func newScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a full or partial scan and write a report",
		Long:  "Runs a full or partial scan of the host and writes a plain-language report to stdout and to the on-disk report file. Per the spec, this is the canonical entry point.",
		RunE:  runScan,
	}
	cmd.Flags().StringVar(&scanFlagCategories, "categories", "", "comma-separated subset of ssh,docker,images,proxy,ssl,hardening (default: all)")
	cmd.Flags().BoolVar(&scanFlagRefreshCVE, "refresh-cve", false, "force a CVE-feed refresh before scanning image categories")
	cmd.Flags().StringVar(&scanFlagCVESource, "cve-source", "", "cve feed source: nvd or osv (overrides the default)")
	cmd.Flags().StringVar(&scanFlagReportDir, "report-dir", "", "where to write the on-disk report (default: ~/.local/share/hostveil/reports/)")
	cmd.Flags().BoolVar(&scanFlagNoFile, "no-report-file", false, "do not write a report file; stdout only")
	return cmd
}

func runScan(cmd *cobra.Command, _ []string) error {
	paths, err := store.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	logger := log.New(os.Stderr, "scan")
	_ = logger

	// Open the store. The file lives at $XDG_DATA_HOME/hostveil/state.db.
	s, err := store.Open(paths.StateDB)
	if err != nil {
		return fmt.Errorf("open state.db: %w", err)
	}
	defer s.Close()

	cats := parseScanCategories(scanFlagCategories)

	// Run the orchestrator.
	result, err := scan.Run(cmd.Context(), s, cats)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Build the host row from the same fingerprint the orchestrator used.
	host, _ := s.GetHost(cmd.Context(), result.Run.HostID)
	if host.ID == "" {
		host = model.Host{ID: result.Run.HostID, Hostname: "(unknown)"}
	}

	// Render the report.
	r := report.BuildRunFromScanRun(result.Run, result.Findings, host)
	reportDir := scanFlagReportDir
	if reportDir == "" {
		reportDir = paths.Reports
	}
	sink := report.Sink{ReportDir: reportDir, NoFile: scanFlagNoFile}
	written, err := sink.Write(r)
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	if written != "" {
		// Patch the persisted row with the on-disk path.
		result.Run.ReportPath = written
		_ = s.UpdateReportPath(cmd.Context(), result.Run.ID, written)
	}

	// Exit code contract: 0 = no high/critical, 1 = at least one
	// high/critical, 2 = scan errored (we'd have returned early above).
	if result.Run.HostveilExitCode == 1 {
		// Tell the cobra root to set the right exit code by returning
		// nil (success) here and letting the orchestrator's
		// HostveilExitCode propagate via os.Exit in main.
		// For v3.0.0-alpha we return an error string; the exit code
		// mapping is handled in cmd/hostveil/main.go.
		return errHit()
	}
	return nil
}

// HitError is the sentinel returned by the scan subcommand when the
// run produced at least one high or critical finding. main.go (and
// Execute) translate it to exit code 1.
type HitError struct{}

func (HitError) Error() string { return "high or critical finding detected" }
func errHit() error            { return HitError{} }

func parseScanCategories(s string) []model.Category {
	if s == "" {
		return nil
	}
	out := []model.Category{}
	current := ""
	for _, r := range s {
		if r == ',' {
			if c, ok := modelCategory(current); ok {
				out = append(out, c)
			}
			current = ""
			continue
		}
		current += string(r)
	}
	if c, ok := modelCategory(current); ok {
		out = append(out, c)
	}
	return out
}

func modelCategory(s string) (model.Category, bool) {
	switch s {
	case "ssh":
		return model.CategorySSH, true
	case "docker":
		return model.CategoryDocker, true
	case "images", "image_cve":
		return model.CategoryImageCVE, true
	case "proxy", "reverse_proxy":
		return model.CategoryReverseProxy, true
	case "ssl", "ssl_tls":
		return model.CategorySSLTLS, true
	case "hardening", "hardening_firewall", "hardening_fail2ban", "hardening_unattended", "hardening_sysctl", "hardening_updates":
		return model.Category(s), true
	}
	return "", false
}

// reportPath is a small helper used in tests to assert the on-disk
// path matches the timestamped convention.
func reportPathFor(ts time.Time, dir string) string {
	return filepath.Join(dir, "hostveil-"+ts.UTC().Format("20060102-150405")+".txt")
}
