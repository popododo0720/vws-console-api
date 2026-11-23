//go:build !linux

package proxmox

import "os"

// fileIdentity is unknown here, so no file beside a tombstone is taken for
// the one it removed.
func fileIdentity(string, os.FileInfo) fileID { return fileID{} }
