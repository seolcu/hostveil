package lynis

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/seolcu/hostveil/internal/domain"
)

var reportPath = "/tmp/hostveil-lynis.dat"

func Scan() ([]domain.Finding, error) {
	os.Remove(reportPath)

	if err := runLynis(); err != nil {
		return nil, err
	}

	findings, err := parseReport()
	os.Remove(reportPath)
	return findings, err
}

func runLynis() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lynis", "audit", "system", "--quiet", "--report-file", reportPath)
	return cmd.Run()
}

func parseReport() ([]domain.Finding, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("lynis report not found: %w", err)
	}

	var findings []domain.Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "warning[]="):
			f := parseEntry(line, domain.SeverityHigh)
			if f != nil {
				findings = append(findings, *f)
			}
		case strings.HasPrefix(line, "suggestion[]="):
			f := parseEntry(line, domain.SeverityMedium)
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

// parseEntry parses a lynis report entry line:
//   warning[]=TEST_ID|Description|Remediation|Extra
//   suggestion[]=TEST_ID|Description|Remediation|Extra
func parseEntry(line string, sev domain.Severity) *domain.Finding {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return nil
	}
	parts := strings.Split(line[eq+1:], "|")
	if len(parts) < 2 {
		return nil
	}

	id := strings.TrimSpace(parts[0])
	desc := strings.TrimSpace(parts[1])
	if id == "" || desc == "" {
		return nil
	}

	var howToFix string
	if len(parts) >= 3 {
		howToFix = strings.TrimSpace(parts[2])
	}

	return &domain.Finding{
		ID:          "lynis." + id,
		Title:       desc,
		Description: desc,
		HowToFix:    howToFix,
		Severity:    sev,
		Source:      domain.SourceLynis,
		Service:     "host",
		Remediation: domain.RemediationUnavailable,
	}
}
