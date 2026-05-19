package domain

import "testing"

func TestSourceString(t *testing.T) {
	tests := []struct {
		s    Source
		want string
	}{
		{SourceNativeCompose, "native_compose"},
		{SourceNativeHost, "native_host"},
		{SourceTrivy, "trivy"},
		{SourceLynis, "lynis"},
		{SourceDockle, "dockle"},
		{SourceGitleaks, "gitleaks"},
		{Source(99), "unknown"},
	}
	for _, tt := range tests {
		if tt.s.String() != tt.want {
			t.Errorf("String() = %q, want %q", tt.s.String(), tt.want)
		}
	}
}

func TestAllSources(t *testing.T) {
	sources := AllSources()
	if len(sources) != 6 {
		t.Errorf("AllSources() returned %d, want 6", len(sources))
	}
}
