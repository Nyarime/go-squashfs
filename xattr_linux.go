//go:build linux

package squashfs

import (
	"strings"
	"syscall"
)

func readXattrs(path string) map[string][]byte {
	sz, err := syscall.Listxattr(path, nil)
	if err != nil || sz <= 0 { return nil }
	buf := make([]byte, sz)
	sz, err = syscall.Listxattr(path, buf)
	if err != nil || sz <= 0 { return nil }

	result := map[string][]byte{}
	names := strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00")
	for _, name := range names {
		if name == "" { continue }
		vsz, err := syscall.Getxattr(path, name, nil)
		if err != nil || vsz < 0 { continue }
		val := make([]byte, vsz)
		vsz, err = syscall.Getxattr(path, name, val)
		if err != nil { continue }
		result[name] = val[:vsz]
	}
	if len(result) == 0 { return nil }
	return result
}

func getStatUID(fi interface{}) (uint32, uint32) {
	if stat, ok := fi.(*syscall.Stat_t); ok {
		return stat.Uid, stat.Gid
	}
	return 0, 0
}

func getDevMajorMinor(fi interface{}) (uint32, uint32) {
	if stat, ok := fi.(*syscall.Stat_t); ok {
		major := uint32((stat.Rdev >> 8) & 0xff)
		minor := uint32(stat.Rdev & 0xff)
		return major, minor
	}
	return 0, 0
}

func isDeviceNode(fi interface{}) bool {
	if stat, ok := fi.(*syscall.Stat_t); ok {
		mode := stat.Mode
		return mode&syscall.S_IFBLK != 0 || mode&syscall.S_IFCHR != 0
	}
	return false
}
