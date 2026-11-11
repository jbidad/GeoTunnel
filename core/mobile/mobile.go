// Package mobile is the gomobile-bindable API of the GeoTunnel core for
// Android (.aar) and iOS (.xcframework). Everything crosses the boundary as
// strings (JSON) or basic types.
//
//	gomobile bind -target=android -javapkg app.geotunnel ./mobile  -> app.geotunnel.mobile.Mobile
//	gomobile bind -target=ios -prefix GT ./mobile                   -> GTMobile...
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sagernet/sing/common/control"

	"geotunnel/core/config"
	"geotunnel/core/engine"
	"geotunnel/core/geo"
	"geotunnel/core/ipc"
	"geotunnel/core/webapp"
)

var (
	mu        sync.Mutex
	hub       = engine.NewLogHub(2000, nil) // lives as long as the app; follows the current engine's scrubber
	eng       = engine.New(engine.Options{Logs: hub})
	dataDir   string
	lastState string
	stopLogs  func()
)

// Version of the core.
func Version() string { return ipc.Version }

// SetDataDir sets where the core keeps its cache (Android:
// Context.getFilesDir(); iOS: the app group container). Call before Start.
func SetDataDir(dir string) {
	mu.Lock()
	defer mu.Unlock()
	dataDir = dir
}

// Start runs the engine. platform may be nil when no profile needs the TUN
// (web-container-only use); then only the per-profile local inbounds exist.
func Start(stateJSON string, platform Platform) error {
	mu.Lock()
	defer mu.Unlock()
	if eng.Running() {
		return errors.New("already running")
	}
	opts := engine.Options{Logs: hub, DataDir: dataDir}
	if platform != nil {
		opts.Platform = newPlatformAdapter(platform)
	}
	eng = engine.New(opts)
	if err := eng.Start([]byte(stateJSON)); err != nil {
		return err
	}
	lastState = stateJSON
	return nil
}

// Stop shuts the cores down.
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	return eng.Stop()
}

// Reload swaps the state in a running engine.
func Reload(stateJSON string) error {
	mu.Lock()
	defer mu.Unlock()
	if err := eng.Reload([]byte(stateJSON)); err != nil {
		return err
	}
	lastState = stateJSON
	return nil
}

// Running reports whether the cores are up.
func Running() bool { return eng.Running() }

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func ctx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// TestOutbound measures one outbound; stateJSON may be "" to reuse the
// running state. Returns engine.TestResult as JSON.
func TestOutbound(stateJSON, outboundID string) string {
	if stateJSON == "" {
		mu.Lock()
		stateJSON = lastState
		mu.Unlock()
	}
	c, cancel := ctx(45 * time.Second)
	defer cancel()
	return toJSON(eng.TestOutbound(c, []byte(stateJSON), outboundID))
}

// GeoLookup returns geo.Derived JSON for a running profile.
func GeoLookup(profileID string, force bool) (string, error) {
	c, cancel := ctx(60 * time.Second)
	defer cancel()
	d, err := eng.GeoLookup(c, profileID, force)
	if err != nil {
		return "", err
	}
	return toJSON(d), nil
}

// ProfilePort is the SOCKS5/HTTP port of a running profile (for
// androidx.webkit.ProxyController).
func ProfilePort(profileID string) (int32, error) {
	p, err := eng.ProfilePort(profileID)
	return int32(p), err
}

// Stats returns engine.Stats JSON.
func Stats() string { return toJSON(eng.Stats()) }

// LeakTest runs the network checks for a profile: {"report":..,"real":..}.
func LeakTest(profileID string, compareDirect bool) (string, error) {
	c, cancel := ctx(120 * time.Second)
	defer cancel()
	rep, real, err := eng.LeakTestNetwork(c, profileID, engine.LeakOptions{CompareDirect: compareDirect})
	if err != nil {
		return "", err
	}
	rep.Finish()
	return toJSON(map[string]any{"report": rep, "real": real}), nil
}

// EvaluateBrowser scores what a container page observed (JSON from the
// leak probe) against the profile's expected values. Returns []Check JSON.
func EvaluateBrowser(expectedJSON, observedJSON, realJSON string) (string, error) {
	var exp geo.Derived
	var obs engine.BrowserObserved
	if err := json.Unmarshal([]byte(expectedJSON), &exp); err != nil {
		return "", err
	}
	if err := json.Unmarshal([]byte(observedJSON), &obs); err != nil {
		return "", err
	}
	var real *engine.RealIPs
	if realJSON != "" && realJSON != "null" {
		real = &engine.RealIPs{}
		if err := json.Unmarshal([]byte(realJSON), real); err != nil {
			return "", err
		}
	}
	return toJSON(engine.EvaluateBrowser(exp, obs, real)), nil
}

// LeakProbeJS returns the read-only leak probe for the WebView container
// (evaluate it in a page loaded through the profile, then pass the result to
// EvaluateBrowser). echoURL "" uses the default header echo service.
func LeakProbeJS(echoURL string) string { return webapp.LeakProbe(echoURL) }

// ParseImport parses links / subscription bodies / JSON into outbounds.
// Returns config.ImportResult JSON; err is set only when nothing parsed.
func ParseImport(text, group string) (string, error) {
	res, err := config.ParseImport([]byte(text), group)
	if res == nil {
		return "", err
	}
	return toJSON(res), err
}

// ToLink renders an outbound (JSON) as a share link.
func ToLink(outboundJSON string, redact bool) (string, error) {
	var o config.Outbound
	if err := json.Unmarshal([]byte(outboundJSON), &o); err != nil {
		return "", err
	}
	return config.ToLink(&o, redact)
}

// ValidateState checks a state document without starting anything.
func ValidateState(stateJSON string) error {
	_, err := config.ParseState([]byte(stateJSON))
	return err
}

// RecentLogs returns the buffered, scrubbed log lines as JSON.
func RecentLogs() string { return toJSON(hub.Recent()) }

// LogListener receives log lines as they happen.
type LogListener interface {
	OnLog(level, source, message string)
}

// SetLogListener streams scrubbed logs to the host (nil to stop).
func SetLogListener(l LogListener) {
	mu.Lock()
	defer mu.Unlock()
	if stopLogs != nil {
		stopLogs()
		stopLogs = nil
	}
	if l == nil {
		return
	}
	ch, stop := hub.Subscribe()
	stopLogs = stop
	go func() {
		for line := range ch {
			l.OnLog(line.Level, line.Source, line.Msg)
		}
	}()
}

// UpdateDefaultInterface is called by the host's network callback whenever
// the underlying (non-VPN) default network changes. name "" = offline.
func UpdateDefaultInterface(name string, index int32, addresses string, expensive, constrained bool) {
	if name == "" {
		sharedMonitor.update(nil, false, false)
		return
	}
	iface := &control.Interface{Index: int(index), Name: name, Flags: net.FlagUp}
	for _, a := range splitLines(addresses) {
		if p, err := netip.ParsePrefix(a); err == nil {
			iface.Addresses = append(iface.Addresses, p)
		}
	}
	sharedMonitor.update(iface, expensive, constrained)
}

// SetMemoryLimitMB caps the Go heap. The iOS packet-tunnel extension is
// killed above ~50 MB, so the extension calls this with ~35 early.
func SetMemoryLimitMB(mb int32) {
	if mb > 0 {
		debug.SetMemoryLimit(int64(mb) << 20)
		debug.SetGCPercent(50)
	}
}

// FreeMemory returns freed heap to the OS (call on memory warnings).
func FreeMemory() { debug.FreeOSMemory() }

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
