// +build darwin

package main

import (
	"syscall"
)

func typeToString(name [16]int8) string {
	var b []byte
	for _, c := range name {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func isNetworkFS(path string) bool {
	var buf syscall.Statfs_t
	if err := syscall.Statfs(path, &buf); err != nil {
		return false
	}
	switch typeToString(buf.Fstypename) {
	case "nfs", "afpfs", "smbfs", "webdav", "devfs":
		return true
	default:
		return false
	}
}
