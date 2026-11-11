package desktop

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEnv(t *testing.T) {
	env := Env([]string{"PATH=/bin", "TZ=Europe/Berlin", "http_proxy=http://old"}, LaunchOptions{Timezone: "Europe/Istanbul", Locale: "tr-TR", ProxyPort: 10801})
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PATH=/bin", "TZ=Europe/Istanbul", "LANG=tr_TR.UTF-8", "LC_ALL=tr_TR.UTF-8",
		"LANGUAGE=tr_TR:tr", "ALL_PROXY=socks5h://127.0.0.1:10801", "https_proxy=http://127.0.0.1:10801"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s in\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "Europe/Berlin") || strings.Contains(joined, "http://old") {
		t.Error("old values must be replaced")
	}
}

// TestLaunchSetsTZ starts a real child process and checks what time zone it
// sees (the C library honours TZ).
func TestLaunchSetsTZ(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, err := Launch(LaunchOptions{Path: "cmd", Timezone: "Europe/Istanbul"}); err == nil {
			t.Fatal("windows TZ launch must report unsupported")
		}
		return
	}
	out := filepath.Join(t.TempDir(), "out")
	script := filepath.Join(t.TempDir(), "probe.sh")
	os.WriteFile(script, []byte("#!/bin/sh\ndate +%Z%z > "+out+"\necho \"$LANG\" >> "+out+"\n"), 0o755)
	if _, err := Launch(LaunchOptions{Path: script, Timezone: "Asia/Tokyo", Locale: "ja-JP"}); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		if b, _ = os.ReadFile(out); strings.Count(string(b), "\n") >= 2 {
			break
		}
	}
	if !strings.Contains(string(b), "JST+0900") || !strings.Contains(string(b), "ja_JP.UTF-8") {
		t.Fatalf("child saw %q", b)
	}
}

func TestListApps(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip()
	}
	apps, err := ListApps()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" {
		found := false
		for _, a := range apps {
			if a.BundleID == "com.apple.Safari" || a.BundleID == "com.apple.calculator" || a.ProcessName == "Calculator" {
				found = true
				if _, err := exec.LookPath(a.Executable); err != nil {
					t.Errorf("%s: executable %s not runnable", a.Name, a.Executable)
				}
			}
		}
		if !found {
			t.Errorf("no system app found among %d apps", len(apps))
		}
	}
}
