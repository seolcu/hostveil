package domain

import "testing"

// TestEscapeCSV_NoSpecialChars asserts the identity case: no commas,
// quotes, or newlines means no transformation.
func TestEscapeCSV_NoSpecialChars(t *testing.T) {
	cases := []string{
		"",
		"hello",
		"nginx:latest",
		"with spaces only",
		"slash/path/like",
	}
	for _, c := range cases {
		if got := EscapeCSV(c); got != c {
			t.Errorf("EscapeCSV(%q) = %q, want identity", c, got)
		}
	}
}

// TestEscapeCSV_Comma asserts the comma-only case is wrapped in
// quotes but the content is otherwise untouched.
func TestEscapeCSV_Comma(t *testing.T) {
	got := EscapeCSV("a,b")
	want := `"a,b"`
	if got != want {
		t.Errorf("EscapeCSV(%q) = %q, want %q", "a,b", got, want)
	}
}

// TestEscapeCSV_Quote asserts embedded double quotes are doubled per
// RFC 4180. This is the most error-prone case for CSV serializers.
func TestEscapeCSV_Quote(t *testing.T) {
	cases := map[string]string{
		`a"b`:   `"a""b"`,
		`"`:     `""""`,
		`a"b"c`: `"a""b""c"`,
	}
	for in, want := range cases {
		if got := EscapeCSV(in); got != want {
			t.Errorf("EscapeCSV(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestEscapeCSV_Newlines asserts CR and LF trigger the wrapping
// path, even when there are no other special characters. Excel and
// Google Sheets treat unescaped newlines as record breaks, so any
// field containing a newline must be quoted.
//
// EscapeCSV does not transform the newline itself; RFC 4180 allows
// raw CR/LF inside a quoted field. The function's only job is to
// make sure the field is wrapped in quotes so downstream parsers
// treat it as a single record.
func TestEscapeCSV_Newlines(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"line1\nline2", "\"line1\nline2\""},
		{"line1\rline2", "\"line1\rline2\""},
		{"line1\r\nline2", "\"line1\r\nline2\""},
	}
	for _, c := range cases {
		if got := EscapeCSV(c.in); got != c.want {
			t.Errorf("EscapeCSV(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
