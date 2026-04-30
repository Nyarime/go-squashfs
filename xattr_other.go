//go:build !linux

package squashfs

func readXattrs(path string) map[string][]byte { return nil }
func getStatUID(fi interface{}) (uint32, uint32) { return 0, 0 }
func getDevMajorMinor(fi interface{}) (uint32, uint32) { return 0, 0 }
func isDeviceNode(fi interface{}) bool { return false }
