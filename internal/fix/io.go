package fix

import "os"

// osWriteFileReal and osReadFileReal are the stdlib implementations,
// split out so the test file's osWriteFile / osReadFile wrappers
// stay above the import line.
func osWriteFileReal(p string, b []byte, _ uint32) error { return os.WriteFile(p, b, 0o644) }
func osReadFileReal(p string) ([]byte, error)             { return os.ReadFile(p) }
func osRename(old, new string) error                     { return os.Rename(old, new) }
func osRemove(p string) error                            { return os.Remove(p) }

// sshMainPath is the path the conflict detector reads. Tests
// override it to point at a temp file so the test does not depend
// on the host's actual /etc/ssh/sshd_config.
var sshMainPath = "/etc/ssh/sshd_config"
