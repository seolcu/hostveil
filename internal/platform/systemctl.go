package platform

import "strings"

// ShowProperty reads one Key=Value line out of `systemctl show` output.
// Records are keyed by name because systemd prints the properties in an order
// of its own, not the order they were asked for.
func ShowProperty(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ExecStartArgv extracts each argv list from `systemctl show --property=
// ExecStart` output, which renders as:
//
//	ExecStart={ path=/usr/bin/dockerd ; argv[]=/usr/bin/dockerd -H fd:// ; ... }
//
// A unit may have several ExecStart entries — a drop-in that clears the
// packaged one with a bare `ExecStart=` and adds its own is the standard way
// to change a daemon's flags — so every argv list is returned.
func ExecStartArgv(out string) []string {
	var argvs []string
	rest := out
	for {
		i := strings.Index(rest, "argv[]=")
		if i < 0 {
			return argvs
		}
		rest = rest[i+len("argv[]="):]
		end := strings.Index(rest, " ; ")
		if end < 0 {
			// Last field before the closing brace.
			if j := strings.Index(rest, " }"); j >= 0 {
				end = j
			} else {
				argvs = append(argvs, rest)
				return argvs
			}
		}
		argvs = append(argvs, rest[:end])
		rest = rest[end:]
	}
}
