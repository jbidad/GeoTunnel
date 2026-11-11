// Package desktop lists installed desktop apps and launches native apps
// with a profile's time zone / locale environment.
package desktop

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// App is one launchable desktop application.
type App struct {
	ID          string `json:"id"` // stable key (bundle id, desktop file id, exe path)
	Name        string `json:"name"`
	Executable  string `json:"executable"`  // absolute path when known
	ProcessName string `json:"processName"` // what sing-box's process_name rule matches
	BundleID    string `json:"bundleId,omitempty"`
	Icon        string `json:"icon,omitempty"` // file path or icon theme name
	Source      string `json:"source"`         // applications | desktop-file | registry | running
}

// ErrUnsupported marks capabilities a platform does not have.
var ErrUnsupported = errors.New("not supported on this platform")

// ListApps returns installed apps sorted by name.
func ListApps() ([]App, error) {
	apps, err := listApps()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := apps[:0]
	for _, a := range apps {
		if a.Name == "" || seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// LaunchOptions describe a "launch with profile".
type LaunchOptions struct {
	Path      string // .app bundle, executable path, or name on PATH
	Args      []string
	Timezone  string // IANA zone -> TZ
	Locale    string // BCP 47 -> LANG / LC_ALL / LANGUAGE
	ProxyPort int    // >0: export proxy variables pointing at the profile inbound
}

// Env returns the environment a launched app gets.
func Env(base []string, o LaunchOptions) []string {
	env := make([]string, 0, len(base)+8)
	drop := map[string]bool{}
	set := map[string]string{}
	if o.Timezone != "" {
		set["TZ"] = o.Timezone
	}
	if o.Locale != "" {
		posix := PosixLocale(o.Locale)
		lang, _, _ := strings.Cut(posix, ".")
		base2, _, _ := strings.Cut(lang, "_")
		set["LANG"], set["LC_ALL"], set["LANGUAGE"] = posix, posix, lang+":"+base2
	}
	if o.ProxyPort > 0 {
		p := strconv.Itoa(o.ProxyPort)
		set["ALL_PROXY"] = "socks5h://127.0.0.1:" + p
		set["HTTP_PROXY"] = "http://127.0.0.1:" + p
		set["HTTPS_PROXY"] = "http://127.0.0.1:" + p
		set["NO_PROXY"] = "localhost,127.0.0.1,::1"
		for _, k := range []string{"all_proxy", "http_proxy", "https_proxy", "no_proxy"} {
			drop[k] = true
		}
	}
	for _, kv := range base {
		k, _, _ := strings.Cut(kv, "=")
		if _, override := set[k]; override || drop[k] {
			continue
		}
		env = append(env, kv)
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+set[k])
	}
	if o.ProxyPort > 0 {
		p := strconv.Itoa(o.ProxyPort)
		env = append(env, "all_proxy=socks5h://127.0.0.1:"+p, "http_proxy=http://127.0.0.1:"+p,
			"https_proxy=http://127.0.0.1:"+p, "no_proxy=localhost,127.0.0.1,::1")
	}
	return env
}

// PosixLocale maps "tr-TR" to "tr_TR.UTF-8".
func PosixLocale(tag string) string {
	tag = strings.ReplaceAll(tag, "-", "_")
	parts := strings.Split(tag, "_")
	if len(parts) >= 2 {
		return strings.ToLower(parts[0]) + "_" + strings.ToUpper(parts[len(parts)-1]) + ".UTF-8"
	}
	return strings.ToLower(tag) + ".UTF-8"
}

// Launch starts the app detached from the core and returns its pid.
func Launch(o LaunchOptions) (int, error) {
	if o.Timezone != "" && runtime.GOOS == "windows" {
		return 0, fmt.Errorf("per-app time zone on Windows: %w (needs the experimental hook, not in v1)", ErrUnsupported)
	}
	if o.Timezone != "" {
		if _, err := time.LoadLocation(o.Timezone); err != nil {
			return 0, fmt.Errorf("unknown time zone %q", o.Timezone)
		}
	}
	path, err := resolveExecutable(o.Path)
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(path, o.Args...)
	cmd.Env = Env(os.Environ(), o)
	cmd.Dir = filepath.Dir(path)
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	go cmd.Wait() // reap
	return pid, nil
}
