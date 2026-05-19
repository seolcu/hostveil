package domain

import "testing"

func TestScopeString(t *testing.T) {
	tests := []struct {
		s    Scope
		want string
	}{
		{ScopeService, "service"},
		{ScopeImage, "image"},
		{ScopeHost, "host"},
		{ScopeProject, "project"},
		{Scope(99), "unknown"},
	}
	for _, tt := range tests {
		if tt.s.String() != tt.want {
			t.Errorf("String() = %q, want %q", tt.s.String(), tt.want)
		}
	}
}
