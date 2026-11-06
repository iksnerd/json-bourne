//go:build unix

package jb

import (
	"fmt"
	"os"
	"syscall"
)

func writableDir(dir string) error { return syscall.Access(dir, 0x2|0x1) } // W_OK|X_OK
func writableFile(p string) error  { return syscall.Access(p, 0x2) }       // W_OK

// ownerMismatch is "" when the file belongs to the user running jb.
func ownerMismatch(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Sprintf("owned by uid %d, jb runs as uid %d", st.Uid, os.Getuid())
	}
	return ""
}
