package model

import "time"

// ScanRunStatus is the locked enum for ScanRun.status.
type ScanRunStatus string

const (
	ScanRunRunning ScanRunStatus = "running"
	ScanRunSuccess ScanRunStatus = "success"
	ScanRunPartial ScanRunStatus = "partial"
	ScanRunError   ScanRunStatus = "error"
)

// CategorySkip is why a category was skipped during a scan.
type CategorySkip struct {
	Category Category `json:"category"`
	Reason   string   `json:"reason"` // not_applicable | missing_prerequisite | elevation_denied | headless_no_tty | unsupported_platform | internal_error
	Detail   string   `json:"detail,omitempty"`
}

// ScanRun is a single execution of the scan.
type ScanRun struct {
	ID                     string         `json:"id"`
	HostID                 string         `json:"host_id"`
	StartedAt              time.Time      `json:"started_at"`
	FinishedAt             *time.Time     `json:"finished_at,omitempty"`
	Status                 ScanRunStatus  `json:"status"`
	CategoriesScanned      []Category     `json:"categories_scanned"`
	CategoriesSkipped      []CategorySkip `json:"categories_skipped"`
	FindingCountCritical   int            `json:"finding_count_critical"`
	FindingCountHigh       int            `json:"finding_count_high"`
	FindingCountMedium     int            `json:"finding_count_medium"`
	FindingCountLow        int            `json:"finding_count_low"`
	HostveilVersion        string         `json:"hostveil_version"`
	CVEFEEDRefreshed       bool           `json:"cve_feed_refreshed"`
	CVEFEEDRefreshSkipped  string         `json:"cve_feed_refresh_skipped_reason,omitempty"`
	ReportPath             string         `json:"report_path,omitempty"`
	HostveilExitCode       int            `json:"hostveil_exit_code"`
}
