package main

import (
	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/fix"
	"github.com/seolcu/hostveil/internal/scan"
)

func launchScanners(live *domain.ScanProgress, reg *fix.Registry) {
	go scan.RunSingleTool(live, reg, "compose")
	go scan.RunSingleTool(live, reg, "trivy")
	go scan.RunSingleTool(live, reg, "lynis")
}

func skipScanners(live *domain.ScanProgress) {
	live.SetToolStatus("compose", domain.ToolSkipped, "Skipped (--no-scan)")
	live.SetToolStatus("trivy", domain.ToolSkipped, "Skipped (--no-scan)")
	live.SetToolStatus("lynis", domain.ToolSkipped, "Skipped (--no-scan)")
	live.Finalize()
}
