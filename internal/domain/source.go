package domain

import "strings"

type Source int

const (
	SourceNativeCompose Source = iota
	SourceNativeHost
	SourceTrivy
	SourceLynis
	SourceDockle
	SourceGitleaks
)

func (s Source) String() string {
	switch s {
	case SourceNativeCompose:
		return "native_compose"
	case SourceNativeHost:
		return "native_host"
	case SourceTrivy:
		return "trivy"
	case SourceLynis:
		return "lynis"
	case SourceDockle:
		return "dockle"
	case SourceGitleaks:
		return "gitleaks"
	default:
		return "unknown"
	}
}

func ParseSource(s string) (Source, bool) {
	switch strings.ToLower(s) {
	case "native_compose":
		return SourceNativeCompose, true
	case "native_host":
		return SourceNativeHost, true
	case "trivy":
		return SourceTrivy, true
	case "lynis":
		return SourceLynis, true
	case "dockle":
		return SourceDockle, true
	case "gitleaks":
		return SourceGitleaks, true
	default:
		return 0, false
	}
}

func AllSources() []Source {
	return []Source{SourceNativeCompose, SourceNativeHost, SourceTrivy, SourceLynis, SourceDockle, SourceGitleaks}
}
