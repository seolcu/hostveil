package compose

import "os"

// osWriteFile is a tiny helper used by FuzzOpen to put arbitrary bytes
// at a path the parser will see. Kept in a separate file so the fuzz
// test body stays focused on the parser contract.
func osWriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
