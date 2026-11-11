//go:build unix

package mobile

import "syscall"

func dupFd(fd int) (int, error) { return syscall.Dup(fd) }
