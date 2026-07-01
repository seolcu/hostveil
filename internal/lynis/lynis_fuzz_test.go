package lynis

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

// FuzzParseEntry feeds arbitrary input to parseEntry. The function must
// never panic and must never return a Finding whose ID or Title contains
// leading/trailing whitespace (parseEntry is expected to TrimSpace the
// raw parts it pulls from the pipe-separated line).
func FuzzParseEntry(f *testing.F) {
	seeds := []string{
		`warning[]=AUTH-9286|Disable SSH password authentication|Fix it|extra`,
		`suggestion[]=FILE-6310|Fix /etc/shadow permissions|chmod`,
		`warning[]=TEST-1|just a title`,
		`warning[]=|description`,
		`warning[]=TEST-1|`,
		`just some text without equals sign`,
		`warning[]=ONLY_ID`,
		``,
		`=`,
		`||`,
		`warning[]=ID|desc|fix|extra1|extra2|extra3`,
		`warning[]=` + strings.Repeat("A", 4096) + `|desc`,
		`warning[]=ID|` + strings.Repeat("X", 4096),
		"\x00null\x00bytes\x00",
		`warning[]=ID|desc with
embedded newline`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseEntry panicked on %q: %v", line, r)
			}
		}()
		finding := parseEntry(line, domain.SeverityHigh)
		if finding == nil {
			return
		}
		// If the parser returned a finding, its ID and Title must be
		// the trimmed versions of the source parts.
		if finding.ID != strings.TrimSpace(finding.ID) {
			t.Errorf("ID has untrimmed whitespace: %q", finding.ID)
		}
		if finding.Title != strings.TrimSpace(finding.Title) {
			t.Errorf("Title has untrimmed whitespace: %q", finding.Title)
		}
		// ID must start with the lynis. prefix parseEntry adds.
		if !strings.HasPrefix(finding.ID, "lynis.") {
			t.Errorf("ID missing lynis. prefix: %q", finding.ID)
		}
		// Source must always be SourceLynis.
		if finding.Source != domain.SourceLynis {
			t.Errorf("Source = %v, want SourceLynis", finding.Source)
		}
		// Service is always "host" for host-hardening findings.
		if finding.Service != "host" {
			t.Errorf("Service = %q, want host", finding.Service)
		}
	})
}

// FuzzParseManualEntry ensures parseManualEntry never panics and that
// the returned ID is always prefixed "lynis.manual." with an 8-hex suffix.
func FuzzParseManualEntry(f *testing.F) {
	seeds := []string{
		`manual_event[]=Review /etc/passwd permissions`,
		`manual_event[]=`,
		`just text`,
		``,
		`=`,
		`manual_event[]=` + strings.Repeat("Z", 1024),
		"\x00\x00\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseManualEntry panicked on %q: %v", line, r)
			}
		}()
		finding := parseManualEntry(line)
		if finding == nil {
			return
		}
		// ID is the SHA-256 prefix of the text; must be exactly
		// "lynis.manual." + 8 hex chars.
		const prefix = "lynis.manual."
		if !strings.HasPrefix(finding.ID, prefix) {
			t.Fatalf("ID missing %q prefix: %q", prefix, finding.ID)
		}
		suffix := finding.ID[len(prefix):]
		if len(suffix) != 8 {
			t.Fatalf("ID suffix length = %d, want 8: %q", len(suffix), finding.ID)
		}
		for _, r := range suffix {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Fatalf("ID suffix has non-hex char %q: %q", r, finding.ID)
			}
		}
		if finding.Severity != domain.SeverityMedium {
			t.Errorf("Severity = %v, want Medium", finding.Severity)
		}
	})
}

// FuzzParseExceptionEntry ensures parseExceptionEntry never panics and
// either returns nil or returns a finding whose ID starts with
// "lynis.exception".
func FuzzParseExceptionEntry(f *testing.F) {
	seeds := []string{
		`exception_event[]=TEST-1|exception message|details`,
		`exception_event[]=|just a message|`,
		`exception_event[]=`,
		`just text`,
		``,
		`exception_event[]=ID|` + strings.Repeat("Y", 1024),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseExceptionEntry panicked on %q: %v", line, r)
			}
		}()
		finding := parseExceptionEntry(line)
		if finding == nil {
			return
		}
		if !strings.HasPrefix(finding.ID, "lynis.exception") {
			t.Errorf("ID missing lynis.exception prefix: %q", finding.ID)
		}
		if finding.Severity != domain.SeverityLow {
			t.Errorf("Severity = %v, want Low", finding.Severity)
		}
	})
}

// FuzzParseReportFile writes arbitrary bytes to a temp file and runs
// parseReportFile against it. It must never panic; it may return an
// error for unreadable files (but the test writes valid bytes so any
// error is a regression).
func FuzzParseReportFile(f *testing.F) {
	seeds := [][]byte{
		[]byte(`warning[]=AUTH-9286|Disable SSH password authentication|Fix it`),
		[]byte(""),
		[]byte("not a lynis report at all\n"),
		[]byte("warning[]=\n"),
		[]byte("\x00\x01\x02"),
		[]byte(strings.Repeat("warning[]=ID|desc\n", 1000)),
		[]byte("suggestion[]=ID|desc\nmanual_event[]=manual text\nexception_event[]=EXC|message\n"),
		[]byte("warning[]=ID|desc with \x00 null bytes\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := dir + "/report.dat"
		if err := writeFile(path, data); err != nil {
			t.Fatalf("write temp: %v", err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseReportFile panicked: %v", r)
			}
		}()
		// parseReportFile returns no error today, but if the file
		// becomes unreadable in the future, the contract is: don't
		// panic. Both nil and a non-nil error are acceptable.
		_, _ = parseReportFile(path)
	})
}
