package lynis

import "os"

// writeFile is a thin wrapper kept next to the fuzz test so the fuzz
// body stays short and the helper is clearly test-only.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
