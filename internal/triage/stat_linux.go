package triage

import (
	"io/fs"
	"syscall"
	"time"
)

func statOf(info fs.FileInfo) (fileStat, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStat{}, false
	}
	return fileStat{
		dev:   uint64(st.Dev), // uint32 on some architectures
		uid:   st.Uid,
		size:  st.Size,
		mtime: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)).UTC(), // int32 on 32-bit architectures
		ctime: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UTC(), // int32 on 32-bit architectures
	}, true
}
