//go:build darwin

package mobile

import "golang.org/x/sys/unix"

// tunnelName reads the utun interface name (SYSPROTO_CONTROL=2,
// UTUN_OPT_IFNAME=2).
func tunnelName(fd int32) (string, error) {
	return unix.GetsockoptString(int(fd), 2, 2)
}
