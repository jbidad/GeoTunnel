//go:build !linux && !darwin

package mobile

import "errors"

// The binding only ships for Android and iOS; this keeps `go build ./...`
// working on other hosts (e.g. Windows CI).
func tunnelName(int32) (string, error) {
	return "", errors.New("tun not supported on this OS")
}
