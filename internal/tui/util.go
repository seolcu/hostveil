package tui

import (
	"fmt"
	"strconv"
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
	short := fmt.Sprintf("%s (1m) / %s (5m) / %s (15m)", fields[0], fields[1], fields[2])
	if detailed && len(fields) >= 5 {
		short += fmt.Sprintf("\nProcesses: %s\nLast PID: %s", fields[3], fields[4])
	}
	return short
}

func formatUptime(raw string) string {
	s := strings.TrimSuffix(raw, "s")
	parts := strings.SplitN(s, ".", 2)
	total, err := strconv.Atoi(parts[0])
	if err != nil {
		return raw
	}
	d := total / 86400
	h := (total % 86400) / 3600
	m := (total % 3600) / 60
	sec := total % 60

	var result []string
	if d > 0 {
		result = append(result, fmt.Sprintf("%dd", d))
	}
	if h > 0 {
		result = append(result, fmt.Sprintf("%dh", h))
	}
	if m > 0 {
		result = append(result, fmt.Sprintf("%dm", m))
	}
	if sec > 0 || len(result) == 0 {
		result = append(result, fmt.Sprintf("%ds", sec))
	}
	return strings.Join(result, " ")
}
