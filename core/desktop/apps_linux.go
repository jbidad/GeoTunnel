//go:build linux && !android

package desktop

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func listApps() ([]App, error) {
	home, _ := os.UserHomeDir()
	dirs := []string{
		"/usr/share/applications", "/usr/local/share/applications",
		filepath.Join(home, ".local/share/applications"),
		"/var/lib/flatpak/exports/share/applications",
		filepath.Join(home, ".local/share/flatpak/exports/share/applications"),
		"/var/lib/snapd/desktop/applications",
	}
	var apps []App
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			if a, ok := parseDesktopFile(filepath.Join(dir, e.Name())); ok {
				apps = append(apps, a)
			}
		}
	}
	return apps, nil
}

// parseDesktopFile reads the [Desktop Entry] group of a .desktop file.
func parseDesktopFile(path string) (App, bool) {
	f, err := os.Open(path)
	if err != nil {
		return App{}, false
	}
	defer f.Close()
	kv := map[string]string{}
	inEntry := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inEntry = line == "[Desktop Entry]"
			continue
		}
		if !inEntry || line == "" || line[0] == '#' {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			k = strings.TrimSpace(k)
			if _, dup := kv[k]; !dup {
				kv[k] = strings.TrimSpace(v)
			}
		}
	}
	if kv["Type"] != "Application" || kv["NoDisplay"] == "true" || kv["Hidden"] == "true" || kv["Exec"] == "" {
		return App{}, false
	}
	argv := splitExec(kv["Exec"])
	if len(argv) == 0 {
		return App{}, false
	}
	exe := argv[0]
	if p, err := exec.LookPath(exe); err == nil {
		exe = p
	}
	id := strings.TrimSuffix(filepath.Base(path), ".desktop")
	return App{ID: id, Name: kv["Name"], Executable: exe, ProcessName: filepath.Base(exe), Icon: kv["Icon"], Source: "desktop-file"}, true
}

// splitExec splits an Exec= value and drops %f/%U style field codes.
func splitExec(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			t := cur.String()
			if !(len(t) == 2 && t[0] == '%') {
				out = append(out, t)
			}
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == ' ' && !inQuote:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	// env FOO=bar app ... -> app
	for len(out) > 1 && (filepath.Base(out[0]) == "env" || strings.Contains(out[0], "=")) {
		out = out[1:]
	}
	return out
}

func resolveExecutable(p string) (string, error) { return exec.LookPath(p) }

func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
