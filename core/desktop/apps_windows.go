//go:build windows

package desktop

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func listApps() ([]App, error) {
	var apps []App
	roots := []struct {
		key  registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, r := range roots {
		k, err := registry.OpenKey(r.key, r.path, registry.ENUMERATE_SUB_KEYS|registry.READ)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		for _, n := range names {
			sk, err := registry.OpenKey(k, n, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			icon, _, _ := sk.GetStringValue("DisplayIcon")
			sysComp, _, _ := sk.GetIntegerValue("SystemComponent")
			sk.Close()
			exe := strings.Trim(strings.SplitN(icon, ",", 2)[0], `"`)
			if name == "" || sysComp == 1 || !strings.EqualFold(filepath.Ext(exe), ".exe") {
				continue
			}
			apps = append(apps, App{ID: strings.ToLower(exe), Name: name, Executable: exe, ProcessName: filepath.Base(exe), Icon: exe, Source: "registry"})
		}
		k.Close()
	}
	apps = append(apps, runningProcesses()...)
	return apps, nil
}

// runningProcesses adds executables of running processes, so apps without
// an uninstall entry can still be picked.
func runningProcesses() []App {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var apps []App
	seen := map[string]bool{}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		name := windows.UTF16ToString(e.ExeFile[:])
		path := processPath(e.ProcessID)
		if path == "" || seen[strings.ToLower(path)] || strings.HasPrefix(strings.ToLower(path), `c:\windows\`) {
			continue
		}
		seen[strings.ToLower(path)] = true
		apps = append(apps, App{ID: strings.ToLower(path), Name: strings.TrimSuffix(name, ".exe"), Executable: path, ProcessName: name, Icon: path, Source: "running"})
	}
	return apps
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func resolveExecutable(p string) (string, error) { return exec.LookPath(p) }

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}
