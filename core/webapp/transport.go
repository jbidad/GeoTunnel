package webapp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/coder/websocket"
)

func startWithTransport(ctx context.Context, cmd *exec.Cmd, o Options) (transport, error) {
	if o.UseDebugPort || runtime.GOOS == "windows" {
		if !o.UseDebugPort {
			return nil, errors.New("webapp: set UseDebugPort on Windows (pipes cannot be inherited)")
		}
		os.Remove(filepath.Join(o.UserDataDir, "DevToolsActivePort"))
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return dialDevToolsPort(ctx, o.UserDataDir, cmd)
	}
	// fd 3: Chrome reads commands; fd 4: Chrome writes replies.
	toChromeR, toChromeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	fromChromeR, fromChromeW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.ExtraFiles = []*os.File{toChromeR, fromChromeW}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	toChromeR.Close()
	fromChromeW.Close()
	return &pipeTransport{w: toChromeW, r: bufio.NewReaderSize(fromChromeR, 1<<20), rc: fromChromeR}, nil
}

func dialDevToolsPort(ctx context.Context, dir string, cmd *exec.Cmd) (transport, error) {
	deadline := time.Now().Add(20 * time.Second)
	file := filepath.Join(dir, "DevToolsActivePort")
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(file)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) >= 2 {
				url := fmt.Sprintf("ws://127.0.0.1:%s%s", strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]))
				c, _, err := websocket.Dial(ctx, url, nil)
				if err != nil {
					return nil, err
				}
				c.SetReadLimit(64 << 20)
				return &wsTransport{c: c}, nil
			}
		}
		if cmd.ProcessState != nil {
			return nil, errors.New("webapp: browser exited during start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("webapp: DevToolsActivePort never appeared")
}
