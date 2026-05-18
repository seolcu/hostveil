package domain

import "strings"

type Scope int

const (
	ScopeService Scope = iota
	ScopeImage
	ScopeHost
	ScopeProject
)

func (s Scope) String() string {
	switch s {
	case ScopeService:
		return "service"
	case ScopeImage:
		return "image"
	case ScopeHost:
		return "host"
	case ScopeProject:
		return "project"
	default:
		return "unknown"
	}
}

func ParseScope(s string) (Scope, bool) {
	switch strings.ToLower(s) {
	case "service":
		return ScopeService, true
	case "image":
		return ScopeImage, true
	case "host":
		return ScopeHost, true
	case "project":
		return ScopeProject, true
	default:
		return 0, false
	}
}
