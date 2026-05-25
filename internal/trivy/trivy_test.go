package trivy

import (
	"os"
	"testing"

	"github.com/seolcu/hostveil/internal/domain"
)

func TestExtractImages(t *testing.T) {
	content := `services:
  web:
    image: nginx
  api:
    image: myapp:latest
`
	path := writeTemp(t, content)
	defer os.Remove(path)

	imgs := extractImages(path)
	if len(imgs) != 2 {
		t.Fatalf("extractImages = %v, want 2 images", imgs)
	}
	if imgs[0] != "nginx" {
		t.Errorf("imgs[0] = %q, want nginx", imgs[0])
	}
	if imgs[1] != "myapp:latest" {
		t.Errorf("imgs[1] = %q, want myapp:latest", imgs[1])
	}
}

func TestExtractImages_NoImage(t *testing.T) {
	content := `services:
  web:
    build: .
`
	path := writeTemp(t, content)
	defer os.Remove(path)

	imgs := extractImages(path)
	if len(imgs) != 0 {
		t.Errorf("expected no images, got %v", imgs)
	}
}

func TestExtractImages_MissingFile(t *testing.T) {
	imgs := extractImages("/nonexistent.yml")
	if imgs != nil {
		t.Errorf("expected nil, got %v", imgs)
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in   string
		want domain.Severity
	}{
		{"CRITICAL", domain.SeverityCritical},
		{"critical", domain.SeverityCritical},
		{"HIGH", domain.SeverityHigh},
		{"High", domain.SeverityHigh},
		{"MEDIUM", domain.SeverityMedium},
		{"medium", domain.SeverityMedium},
		{"LOW", domain.SeverityLow},
		{"Low", domain.SeverityLow},
		{"UNKNOWN", domain.SeverityMedium},   // default
		{"", domain.SeverityMedium},           // default
		{"CRIT", domain.SeverityMedium},       // default (unexpected)
	}
	for _, tt := range tests {
		got := parseSeverity(tt.in)
		if got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s      string
		n      int
		want   string
	}{
		{"hello world", 5, "hello..."},
		{"short", 10, "short"},
		{"exact", 5, "exact"},
		{"", 5, ""},
		{"hello", 0, "..."},
	}
	for _, tt := range tests {
		got := truncate(tt.s, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "hostveil-test-*.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}
