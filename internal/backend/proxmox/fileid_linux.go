//go:build linux

package proxmox

import (
	"os"
	"syscall"
)

// fileIdentity is the device, inode and ctime of info.
func fileIdentity(info os.FileInfo) fileID {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{Dev: st.Dev, Ino: st.Ino, Ctime: st.Ctim.Nano()}
}
