package tui

import (
	"fmt"
	"strings"
)

func pluralize(s string, n int) string {
	if n == 1 {
		return s
	}
	return s + "s"
}

func formatLoadAvg(raw string, detailed bool) string {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return raw
	}
	short := fmt.Sprintf("%s / %s / %s", fields[0], fields[1], fields[2])
	if detailed && len(fields) >= 5 {
		short += fmt.Sprintf("\nProcesses: %s\nLast PID: %s", fields[3], fields[4])
	}
	return short
}

func nextCycle(current string, options []string) string {
	for i, o := range options {
		if o == current {
			return options[(i+1)%len(options)]
		}
	}
	return options[0]
}
