package report

import (
	"strings"
	"testing"
)

func TestRedact_PEMPrivateKey(t *testing.T) {
	in := "config:\n-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\nend"
	got := Redact(in)
	if strings.Contains(got, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("Redact() left a PEM block: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("Redact() did not insert the [REDACTED] marker: %q", got)
	}
}

func TestRedact_URLCredentials(t *testing.T) {
	in := "fetch https://user:secret@example.com/data"
	got := Redact(in)
	if strings.Contains(got, "user:secret") {
		t.Errorf("Redact() left URL credentials: %q", got)
	}
}

func TestRedact_AWSAccessKey(t *testing.T) {
	in := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
	got := Redact(in)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Redact() left an AWS access key: %q", got)
	}
}

func TestRedactMap(t *testing.T) {
	m := map[string]string{
		"username":  "alice",
		"password":  "hunter2",
		"api_key":   "secret-123",
		"comment":   "this is fine",
		"https_url": "https://u:p@example.com/",
	}
	got := RedactMap(m)
	if got["password"] != "[REDACTED]" {
		t.Errorf("password = %q, want [REDACTED]", got["password"])
	}
	if got["api_key"] != "[REDACTED]" {
		t.Errorf("api_key = %q, want [REDACTED]", got["api_key"])
	}
	if got["comment"] != "this is fine" {
		t.Errorf("comment = %q, want unchanged", got["comment"])
	}
	if got["username"] != "alice" {
		t.Errorf("username = %q, want alice", got["username"])
	}
	if strings.Contains(got["https_url"], "u:p") {
		t.Errorf("https_url = %q, credentials should be redacted", got["https_url"])
	}
}

func TestRedactLines(t *testing.T) {
	in := `# comment
password = hunter2
api_key = topsecret
public = keep-me
https_url = https://u:p@example.com/
-----BEGIN OPENSSH PRIVATE KEY-----
abc
-----END OPENSSH PRIVATE KEY-----`
	got := RedactLines(in)
	if strings.Contains(got, "hunter2") {
		t.Errorf("RedactLines() left password value: %q", got)
	}
	if strings.Contains(got, "topsecret") {
		t.Errorf("RedactLines() left api_key value: %q", got)
	}
	if !strings.Contains(got, "public = keep-me") {
		t.Errorf("RedactLines() modified the public line: %q", got)
	}
	if strings.Contains(got, "u:p@") {
		t.Errorf("RedactLines() left URL credentials: %q", got)
	}
	if strings.Contains(got, "BEGIN OPENSSH PRIVATE KEY") {
		t.Errorf("RedactLines() left a PEM block: %q", got)
	}
}
