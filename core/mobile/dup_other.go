//go:build !unix

package mobile

import "errors"

func dupFd(int) (int, error) { return 0, errors.New("tun not supported on this OS") }
