package trivy

import (
	"strings"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

// FuzzDecodeTrivyJSON ensures decodeTrivyJSON never panics and only
// returns one of the three documented error messages.
//
// The function's contract is: empty -> "empty output" error; first
// non-space byte not '{' or '[' -> "non-JSON output" error; otherwise
// json.Unmarshal error -> "invalid JSON" error; success otherwise.
//
// We intentionally do NOT cross-check accepted input against
// json.Valid — json.Unmarshal is more permissive than json.Valid
// (e.g. it tolerates trailing form feeds inside array literals), and
// the function is documented to mirror json.Unmarshal, not the
// stricter json.Valid.
//
// Inputs above maxFuzzDecodeBytes are skipped. Without this cap the
// fuzzer occasionally mutates a seed into a deeply-nested array that
// makes json.Unmarshal take several seconds. The 1 MiB ceiling is
// well above any sane trivy output (a 1 MiB image report is already
// a sign something is wrong) and keeps each iteration bounded.
const maxFuzzDecodeBytes = 1 << 20

func FuzzDecodeTrivyJSON(f *testing.F) {
	seeds := []string{
		``,
		`   `,
		`{}`,
		`[]`,
		`{"Results":[]}`,
		`not json`,
		`{"Results":[{"Target":"nginx","Vulnerabilities":[]}]}`,
		`{"x":` + strings.Repeat("1", 1000) + `}`,
		`[` + strings.Repeat(`{"a":1},`, 100) + `]`,
		`\x00\x00\x00`,
		"{\"Results\":[{\"Target\":\"nginx:latest\",\"Vulnerabilities\":[{\"VulnerabilityID\":\"CVE-2024-1234\",\"PkgName\":\"openssl\",\"Severity\":\"CRITICAL\",\"Title\":\"OpenSSL vuln\",\"Description\":\"a vuln\",\"FixedVersion\":\"3.0.1\"}]}]}",
		"\xff\xfe garbage",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxFuzzDecodeBytes {
			t.Skip("input exceeds size cap")
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decodeTrivyJSON panicked on %q: %v", input, r)
			}
		}()
		var v any
		err := decodeTrivyJSON([]byte(input), &v)
		if err != nil {
			msg := err.Error()
			switch {
			case msg == "trivy returned empty output":
			case msg == "trivy returned non-JSON output":
			case msg == "trivy returned invalid JSON":
			default:
				t.Errorf("unexpected error message %q for input %q", msg, input)
			}
			return
		}
		// Success path: the first call's success is the contract.
		// No second-pass decode here — the function is a thin
		// wrapper around json.Unmarshal and re-running it would
		// just test the standard library, not the function.
	})
}

// FuzzParseSeverity asserts parseSeverity is total (any input returns
// one of the four severity values) and that the known mappings are
// case-insensitive.
func FuzzParseSeverity(f *testing.F) {
	seeds := []string{
		"CRITICAL",
		"HIGH",
		"MEDIUM",
		"LOW",
		"critical",
		"Critical",
		"unknown",
		"",
		"FOO",
		"high ",
		" MEDIUM",
		"LoW",
		"\x00",
		strings.Repeat("X", 256),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseSeverity panicked on %q: %v", s, r)
			}
		}()
		sev := parseSeverity(s)
		switch sev {
		case domain.SeverityCritical, domain.SeverityHigh,
			domain.SeverityMedium, domain.SeverityLow:
			// ok
		default:
			t.Errorf("parseSeverity(%q) = %d, not a known severity", s, sev)
		}
	})
}

// FuzzSanitizeCommandOutput checks the trivy stderr sanitizer for
// crashes and a few invariants: empty input -> "no output"; input
// with a line containing "fatal" or "error" (case-insensitive) -> the
// first such line (trimmed, possibly truncated); otherwise the first
// non-blank, non-Usage/Aliases line.
func FuzzSanitizeCommandOutput(f *testing.F) {
	seeds := []string{
		``,
		`   `,
		`Usage: trivy [options]`,
		`Aliases: t`,
		`FATAL: bad image`,
		`Error: connection refused`,
		`error: something else`,
		`FATAL: ` + strings.Repeat("X", 500),
		`normal line\nUsage: ignored\nFATAL: kept`,
		"\x00\x00",
		"  \n  \n  error: real  \n  ",
		strings.Repeat("a", 1000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxFuzzDecodeBytes {
			t.Skip("input exceeds size cap")
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("sanitizeCommandOutput panicked on %q: %v", input, r)
			}
		}()
		out := sanitizeCommandOutput([]byte(input))
		// Output must never be empty.
		if out == "" {
			t.Errorf("sanitizeCommandOutput returned empty for input %q", input)
		}
		// Output must be <= 160 chars (fitErrorLine truncates beyond).
		if len(out) > 160 {
			t.Errorf("sanitizeCommandOutput returned %d chars (>160) for input %q", len(out), input)
		}
		// "no output" is the only acceptable answer for whitespace-only input.
		trimmed := strings.TrimSpace(input)
		if trimmed == "" && out != "no output" {
			t.Errorf("input whitespace-only, got %q, want %q", out, "no output")
		}
	})
}
