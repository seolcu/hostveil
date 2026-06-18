package scan

import (
	"os"
	"runtime"
)

func hostname() (string, error)  { return os.Hostname() }
func machineID() (string, error) { return readMachineID() }

func readMachineID() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			s := string(b)
			if len(s) > 0 && s[len(s)-1] == '\n' {
				s = s[:len(s)-1]
			}
			return s, nil
		}
	}
	return "unknown", nil
}

func arch() string { return runtime.GOARCH }
