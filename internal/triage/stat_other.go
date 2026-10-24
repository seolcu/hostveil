//go:build !linux

package triage

import "io/fs"

// statOf has no ctime or device to offer off Linux, and triage refuses to
// run there anyway: every artifact it collects is a Linux one.
func statOf(info fs.FileInfo) (fileStat, bool) {
	return fileStat{size: info.Size(), mtime: info.ModTime().UTC(), ctime: info.ModTime().UTC()}, true
}
