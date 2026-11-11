//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"time"

	winio "github.com/tailscale/go-winio"
	"golang.org/x/sys/windows/svc"
)

// listenPipe opens a named pipe that only SYSTEM, Administrators and the
// given user SID may open. Without --allow-sid (UI-spawned, unprivileged
// sidecar) the pipe is limited to the creator/owner.
func listenPipe(name, allowSID string) (net.Listener, error) {
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)"
	if allowSID != "" {
		sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + allowSID + ")"
	}
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 1 << 16, OutputBufferSize: 1 << 16})
}

func dialPipe(name string) (net.Conn, error) {
	t := 5 * time.Second
	return winio.DialPipe(name, &t)
}

func listenUnix(string, int) (net.Listener, error) {
	return nil, errors.New("--socket is not used on Windows; use --pipe")
}

func chownPath(string, int) error { return nil } // ACLs come from the service's directory

// runService runs under the Service Control Manager when started as a
// Windows service, otherwise in the foreground.
func runService(run func(ctx context.Context) error) error {
	isSvc, err := svc.IsWindowsService()
	if err != nil || !isSvc {
		ctx, cancel := signalContext()
		defer cancel()
		return run(ctx)
	}
	return svc.Run("GeoTunnelCore", &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-done; err != nil {
					return false, 1
				}
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
