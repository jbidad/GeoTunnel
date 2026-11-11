//go:build !darwin && !windows && (!linux || android)

package desktop

import (
	"os/exec"
)

func listApps() ([]App, error) { return nil, ErrUnsupported }

func resolveExecutable(p string) (string, error) { return "", ErrUnsupported }

func detach(*exec.Cmd) {}
