//go:build linux

package proxmox

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// fileIdentity is the device, inode and birth time of the file at path, whose
// Lstat is info. chmod and chown keep all three; a replacement by temporary
// file and rename changes the inode and the birth time. Where statx reports no
// birth time the identity is the device and inode alone.
func fileIdentity(path string, info os.FileInfo) fileID {
	var stx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_BTIME, &stx)
	if err == nil && stx.Mask&unix.STATX_INO != 0 {
		id := fileID{Dev: unix.Mkdev(stx.Dev_major, stx.Dev_minor), Ino: stx.Ino}
		if stx.Mask&unix.STATX_BTIME != 0 {
			id.Btime = stx.Btime.Sec*1e9 + int64(stx.Btime.Nsec)
		}
		return id
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{Dev: st.Dev, Ino: st.Ino}
}
