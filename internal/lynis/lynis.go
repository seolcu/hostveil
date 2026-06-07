// Package lynis parses Lynis audit reports into domain.Findings.
package lynis

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/seolcu/hostveil/internal/domain"
)

func Scan() ([]domain.Finding, error) {
	f, err := os.CreateTemp("", "hostveil-lynis-*.dat")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	reportPath := f.Name()
	_ = f.Close()
	defer os.Remove(reportPath) //nolint:errcheck // temp file cleanup

	if err := runLynis(reportPath); err != nil {
		return nil, err
	}

	findings, err := parseReportFile(reportPath)
	return findings, err
}

func runLynis(reportPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), domain.LynisAuditTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lynis", "audit", "system", "--quiet", "--report-file", reportPath)
	err1 := cmd.Run()
	if err1 == nil {
		return nil
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), domain.LynisAuditTimeout)
	defer cancel2()

	cmd2 := exec.CommandContext(ctx2, "lynis", "audit", "system", "--quiet", "--logfile", reportPath)
	var stderrBuf strings.Builder
	cmd2.Stderr = &stderrBuf
	err2 := cmd2.Run()
	if err2 != nil {
		stderr := strings.TrimSpace(stderrBuf.String())
		if stderr != "" {
			return fmt.Errorf("first attempt: %w; second attempt: %w: %s", err1, err2, stderr)
		}
		return fmt.Errorf("first attempt: %w; second attempt: %w", err1, err2)
	}
	return nil
}

func parseReportFile(reportPath string) ([]domain.Finding, error) {
	data, err := os.ReadFile(reportPath) //nolint:gosec // temp file created by this package
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
		case strings.HasPrefix(line, "manual_event[]="):
			f := parseManualEntry(line)
			if f != nil {
				findings = append(findings, *f)
			}
		case strings.HasPrefix(line, "exception_event[]="):
			f := parseExceptionEntry(line)
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

// parseEntry parses a lynis report entry line:
//
//	warning[]=TEST_ID|Description|Remediation|Extra
//	suggestion[]=TEST_ID|Description|Remediation|Extra
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

	ev := map[string]string{}
	if len(parts) >= 4 {
		extra := strings.TrimSpace(parts[3])
		if extra != "" {
			ev["extra"] = extra
			switch {
			case id == "FILE-6405" || strings.HasPrefix(id, "FILE-6405"):
				ev["path"] = extra
			case id == "ACCT-9626" || strings.HasPrefix(id, "ACCT-9626"):
				ev["user"] = extra
			case id == "FIRE-4513" || strings.HasPrefix(id, "FIRE-4513"):
				ev["port"] = extra
			}
		}
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
		Evidence:    ev,
	}
}

// parseManualEntry parses manual_event[] lines:
//
//	manual_event[]=text
func parseManualEntry(line string) *domain.Finding {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return nil
	}
	text := strings.TrimSpace(line[eq+1:])
	if text == "" {
		return nil
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(text)))[:8]
	return &domain.Finding{
		ID:          "lynis.manual." + hash,
		Title:       text,
		Description: text,
		HowToFix:    "Manual intervention required. Review Lynis documentation for guidance.",
		Severity:    domain.SeverityMedium,
		Source:      domain.SourceLynis,
		Service:     "host",
		Remediation: domain.RemediationManual,
	}
}

// parseExceptionEntry parses exception_event[] lines:
//
//	exception_event[]=TEST_ID|Message|
func parseExceptionEntry(line string) *domain.Finding {
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return nil
	}
	parts := strings.Split(line[eq+1:], "|")
	if len(parts) < 2 {
		return nil
	}

	id := strings.TrimSpace(parts[0])
	msg := strings.TrimSpace(parts[1])
	if msg == "" {
		return nil
	}

	findingID := "lynis.exception"
	if id != "" {
		findingID = "lynis.exception." + id
	}

	return &domain.Finding{
		ID:          findingID,
		Title:       msg,
		Description: msg,
		HowToFix:    "Check Lynis scan logs for details on this exception.",
		Severity:    domain.SeverityLow,
		Source:      domain.SourceLynis,
		Service:     "host",
		Remediation: domain.RemediationUnavailable,
	}
}
