package report

import (
	"regexp"
	"strings"
)

// Redaction patterns. The list is locked by
// tests/contract/report_json_test.go; adding a pattern is a
// schema_version bump.
var (
	pemPrivateKey   = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
	urlCreds        = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]+://[^\s:@]+:[^\s@]+@`)
	awsAccessKey    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	credFieldNames  = []string{"password", "passwd", "secret", "api_key", "apikey", "token", "bearer", "private_key"}
)

// Redact replaces sensitive values in s with [REDACTED]. It is applied
// to every field that could carry secrets before the report is
// serialized to stdout, to the on-disk file, or sent to the AI layer.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	out = pemPrivateKey.ReplaceAllString(out, "[REDACTED]")
	out = urlCreds.ReplaceAllString(out, "[REDACTED]")
	out = awsAccessKey.ReplaceAllString(out, "[REDACTED]")
	return out
}

// RedactMap applies Redact to every value in m whose key matches one
// of the known credential field names. The match is case-insensitive.
func RedactMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if isCredField(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = Redact(v)
	}
	return out
}

// RedactLines scans line-by-line, redacting a value when its key on
// the previous "key:" line matches a credential field name. Useful
// for INI-style and YAML-style files where settings are line-oriented.
// Every line is also passed through Redact() to catch URL credentials
// and PEM blocks regardless of the key; after the line-by-line pass
// the whole result is passed through Redact() once more so
// multi-line patterns (PEM blocks) are caught.
func RedactLines(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if k, v, ok := splitKV(trimmed); ok {
			if isCredField(k) {
				b.WriteString(k)
				b.WriteString(" = [REDACTED]\n")
				continue
			}
			// Preserve the key, redact the value (URL creds, PEM, etc.)
			// and the original separator / spacing.
			sep := separatorIn(line)
			b.WriteString(k)
			b.WriteString(sep)
			b.WriteString(Redact(v))
			b.WriteString("\n")
			continue
		}
		// Not a key/value line; redact any inline URL credentials or
		// PEM blocks regardless of key.
		b.WriteString(Redact(line))
		b.WriteString("\n")
	}
	return Redact(strings.TrimRight(b.String(), "\n"))
}

// separatorIn returns the original "key<sep>value" separator so we can
// preserve the user's spacing / punctuation in the output.
func separatorIn(line string) string {
	for _, sep := range []string{" = ", " : ", ": ", "="} {
		if i := strings.Index(line, sep); i > 0 {
			return line[i : i+len(sep)]
		}
	}
	return " "
}

func isCredField(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, c := range credFieldNames {
		if n == c {
			return true
		}
	}
	return false
}

// splitKV parses "key value" or "key: value" or "key = value" into
// (key, value, ok). Lines that are comments or empty are not
// key/value lines.
func splitKV(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", "", false
	}
	for _, sep := range []string{" = ", " : ", ": ", "="} {
		if i := strings.Index(line, sep); i > 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):]), true
		}
	}
	return "", "", false
}
