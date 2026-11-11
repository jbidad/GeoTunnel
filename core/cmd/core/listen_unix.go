//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
)

// listenUnix opens a 0600 socket. When the helper runs as root it hands the
// socket to the one user allowed to drive it.
func listenUnix(path string, ownerUID int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace non-socket " + path)
		}
		os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	if ownerUID >= 0 {
		if err := chownPath(path, ownerUID); err != nil {
			l.Close()
			return nil, err
		}
	}
	return l, nil
}

func chownPath(path string, uid int) error { return os.Chown(path, uid, -1) }

func listenPipe(string, string) (net.Listener, error) {
	return nil, errors.New("--pipe is Windows-only; use --socket")
}

func dialPipe(string) (net.Conn, error) { return nil, errors.New("--pipe is Windows-only") }

func runService(run func(ctx context.Context) error) error {
	ctx, cancel := signalContext()
	defer cancel()
	return run(ctx)
}
