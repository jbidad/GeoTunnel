//go:build darwin

package desktop

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type infoPlist struct {
	CFBundleExecutable  string `json:"CFBundleExecutable"`
	CFBundleIdentifier  string `json:"CFBundleIdentifier"`
	CFBundleName        string `json:"CFBundleName"`
	CFBundleDisplayName string `json:"CFBundleDisplayName"`
	CFBundleIconFile    string `json:"CFBundleIconFile"`
}

// readInfoPlist converts (possibly binary) Info.plist with plutil.
func readInfoPlist(app string) (*infoPlist, error) {
	out, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", filepath.Join(app, "Contents", "Info.plist")).Output()
	if err != nil {
		return nil, err
	}
	var p infoPlist
	if err := json.Unmarshal(out, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func listApps() ([]App, error) {
	home, _ := os.UserHomeDir()
	var apps []App
	for _, dir := range []string{"/Applications", "/Applications/Utilities", filepath.Join(home, "Applications"), "/System/Applications"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			p, err := readInfoPlist(path)
			if err != nil || p.CFBundleExecutable == "" {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".app")
			icon := ""
			if p.CFBundleIconFile != "" {
				icon = filepath.Join(path, "Contents", "Resources", p.CFBundleIconFile)
				if filepath.Ext(icon) == "" {
					icon += ".icns"
				}
			}
			id := p.CFBundleIdentifier
			if id == "" {
				id = path
			}
			apps = append(apps, App{
				ID: id, Name: name, BundleID: p.CFBundleIdentifier, Icon: icon, Source: "applications",
				Executable:  filepath.Join(path, "Contents", "MacOS", p.CFBundleExecutable),
				ProcessName: p.CFBundleExecutable,
			})
		}
	}
	return apps, nil
}

// resolveExecutable accepts a .app bundle (runs its CFBundleExecutable so
// the environment reaches the process; `open` would hand it to launchd and
// drop TZ), an absolute path, or a name on PATH.
func resolveExecutable(p string) (string, error) {
	if strings.HasSuffix(strings.TrimSuffix(p, "/"), ".app") {
		info, err := readInfoPlist(p)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", p, err)
		}
		return filepath.Join(p, "Contents", "MacOS", info.CFBundleExecutable), nil
	}
	return exec.LookPath(p)
}

func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
