//go:build linux

package mobile

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func tunnelName(fd int32) (string, error) {
	var ifr [unix.IFNAMSIZ + 64]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return "", fmt.Errorf("TUNGETIFF: %w", syscall.Errno(errno))
	}
	return unix.ByteSliceToString(ifr[:]), nil
}
