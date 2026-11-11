package webapp

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ErrNoBrowser means no Chromium-family browser was found; the UI then
// offers to download the pinned Chromium build.
var ErrNoBrowser = errors.New("no Chrome, Chromium or Edge installation found")

// FindBrowser prefers a user-installed Chrome / Chromium / Edge / Brave.
func FindBrowser() (string, error) {
	var candidates []string
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		for _, root := range []string{"/Applications", filepath.Join(home, "Applications")} {
			candidates = append(candidates,
				root+"/Google Chrome.app/Contents/MacOS/Google Chrome",
				root+"/Chromium.app/Contents/MacOS/Chromium",
				root+"/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
				root+"/Brave Browser.app/Contents/MacOS/Brave Browser",
			)
		}
	case "windows":
		for _, env := range []string{"PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"} {
			if root := os.Getenv(env); root != "" {
				candidates = append(candidates,
					filepath.Join(root, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(root, `Chromium\Application\chrome.exe`),
					filepath.Join(root, `Microsoft\Edge\Application\msedge.exe`),
					filepath.Join(root, `BraveSoftware\Brave-Browser\Application\brave.exe`),
				)
			}
		}
	default:
		for _, name := range []string{"google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "microsoft-edge", "brave-browser"} {
			if p, err := exec.LookPath(name); err == nil {
				candidates = append(candidates, p)
			}
		}
		candidates = append(candidates, "/snap/bin/chromium")
	}
	if p := os.Getenv("GEOTUNNEL_BROWSER"); p != "" {
		candidates = append([]string{p}, candidates...)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	return "", ErrNoBrowser
}
