// Package engine runs GeoTunnel's cores: Xray-core for the v2ray-family
// outbounds and sing-box for TUN, per-app routing, per-profile inbounds and
// remote DNS. It exposes the stable API the UI layers use (Start, Stop,
// Reload, TestOutbound, GeoLookup, Stats, logs).
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	xcore "github.com/xtls/xray-core/core"

	"geotunnel/core/config"
	"geotunnel/core/geo"
)

// Options configure an Engine.
type Options struct {
	// Platform is sing-box's platform hook (TUN fd, socket protection,
	// connection owner lookup) on Android/iOS; nil on desktop.
	Platform adapter.PlatformInterface
	// LogBuffer is the number of log lines kept (default 2000).
	LogBuffer int
	// GeoProviders overrides geo.DefaultProviders (tests, self-hosted).
	GeoProviders []geo.Provider
}

// Engine is safe for concurrent use.
type Engine struct {
	opts  Options
	scrub config.Scrubber
	Logs  *LogHub

	mu        sync.Mutex
	state     *config.State
	built     *config.Built
	xray      *xcore.Instance
	sb        *singBox
	track     *tracker
	startedAt time.Time

	geoCache geo.Cache
	geoMu    sync.Mutex
	jitters  map[string]geo.Jitter
	derived  map[string]geo.Derived
}

// New creates an idle engine.
func New(opts Options) *Engine {
	if opts.LogBuffer == 0 {
		opts.LogBuffer = 2000
	}
	e := &Engine{opts: opts, jitters: map[string]geo.Jitter{}, derived: map[string]geo.Derived{}}
	e.Logs = NewLogHub(opts.LogBuffer, &e.scrub)
	return e
}

// ErrNotRunning is returned by calls that need a running engine.
var ErrNotRunning = errors.New("engine is not running")

// Running reports whether the cores are up.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sb != nil
}

// Start parses the state, builds both configs and starts the cores.
func (e *Engine) Start(stateJSON []byte) error {
	st, err := config.ParseState(stateJSON)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sb != nil {
		return errors.New("already running; use Reload")
	}
	return e.startLocked(st)
}

func (e *Engine) startLocked(st *config.State) error {
	e.scrub.SetFromOutbounds(st.Outbounds)
	built, err := config.Build(st, allocXrayInbound)
	if err != nil {
		return err
	}
	for _, w := range built.Warnings {
		e.Logs.Write("engine", "warn", w)
	}
	var xi *xcore.Instance
	if built.Xray != nil {
		setXrayHub(e.Logs)
		if xi, err = startXray(built.Xray); err != nil {
			return err
		}
	}
	trk := newTracker()
	sb, err := startSingBox(built.SingBox, e.opts.Platform, e.Logs, trk)
	if err != nil {
		if xi != nil {
			xi.Close()
		}
		return err
	}
	e.state, e.built, e.xray, e.sb, e.track = st, built, xi, sb, trk
	e.startedAt = time.Now()
	e.Logs.Write("engine", "info", fmt.Sprintf("started: %d profiles, %d outbounds", len(st.Profiles), len(st.Outbounds)))
	return nil
}

// Stop shuts both cores down.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLocked()
}

func (e *Engine) stopLocked() error {
	var errs []error
	if e.sb != nil {
		errs = append(errs, e.sb.Close())
		e.sb = nil
	}
	if e.xray != nil {
		errs = append(errs, e.xray.Close())
		e.xray = nil
	}
	if e.state != nil {
		e.Logs.Write("engine", "info", "stopped")
	}
	return errors.Join(errs...)
}

// Reload swaps in a new state. Inbound ports are reused, so the old cores
// stop first; if the new state fails to start, the previous one is restored.
func (e *Engine) Reload(stateJSON []byte) error {
	st, err := config.ParseState(stateJSON)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	prev := e.state
	if err := e.stopLocked(); err != nil {
		e.Logs.Write("engine", "warn", "stop during reload: "+err.Error())
	}
	if err := e.startLocked(st); err != nil {
		if prev != nil {
			if rerr := e.startLocked(prev); rerr != nil {
				return fmt.Errorf("reload failed (%v) and previous state did not restart: %w", err, rerr)
			}
		}
		return fmt.Errorf("reload failed, previous state restored: %w", err)
	}
	// Re-derive geo for profiles whose outbound changed.
	e.geoMu.Lock()
	for id := range e.derived {
		np := st.ProfileByID(id)
		if np == nil || prev == nil || prev.ProfileByID(id) == nil || prev.ProfileByID(id).Outbound != np.Outbound {
			delete(e.derived, id)
		}
	}
	e.geoMu.Unlock()
	return nil
}

// Built returns the generated configs, credentials redacted (for the Logs /
// diagnostics screen and bug reports).
func (e *Engine) Built() (xray, singbox []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.built == nil {
		return nil, nil, ErrNotRunning
	}
	return config.RedactJSONConfig(e.built.Xray), config.RedactJSONConfig(e.built.SingBox), nil
}

// ProfilePort returns the local SOCKS5/HTTP port of a profile.
func (e *Engine) ProfilePort(profileID string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == nil {
		return 0, ErrNotRunning
	}
	p := e.state.ProfileByID(profileID)
	if p == nil {
		return 0, fmt.Errorf("unknown profile %q", profileID)
	}
	return p.LocalPort, nil
}

// Stats is the Stats() answer.
type Stats struct {
	Running   bool          `json:"running"`
	UptimeSec int64         `json:"uptimeSec"`
	Traffic   []TrafficStat `json:"traffic"`
	// ProfileOutbound maps profile -> outbound tag ("" = blocked).
	ProfileOutbound map[string]string `json:"profileOutbound"`
	Warnings        []string          `json:"warnings,omitempty"`
}

func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sb == nil {
		return Stats{}
	}
	return Stats{
		Running:         true,
		UptimeSec:       int64(time.Since(e.startedAt).Seconds()),
		Traffic:         e.track.snapshot(),
		ProfileOutbound: e.built.ProfileOutbound,
		Warnings:        e.built.Warnings,
	}
}

// TestResult is the TestOutbound answer.
type TestResult struct {
	OutboundID string `json:"outboundId"`
	LatencyMs  int64  `json:"latencyMs"`
	IP         string `json:"ip,omitempty"`
	Country    string `json:"country,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TestOutbound starts a throwaway core pair for one outbound, measures an
// HTTP round trip to the test URL through it and looks up the exit IP.
// It never touches the running profiles.
func (e *Engine) TestOutbound(ctx context.Context, stateJSON []byte, outboundID string) TestResult {
	res := TestResult{OutboundID: outboundID}
	st, err := config.ParseState(stateJSON)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if st.OutboundByID(outboundID) == nil {
		res.Error = "unknown outbound"
		return res
	}
	port, err := freePort()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	tmp := &config.State{
		Outbounds: st.Outbounds,
		Profiles:  []*config.Profile{{ID: "test", Outbound: outboundID, LocalPort: port}},
		Settings:  config.Settings{Platform: st.Settings.Platform, LogLevel: "warn", TestURL: st.Settings.TestURL},
	}
	if err := tmp.Normalize(); err != nil {
		res.Error = err.Error()
		return res
	}
	built, err := config.Build(tmp, allocXrayInbound)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if built.ProfileOutbound["test"] == "" {
		res.Error = "outbound cannot be run: " + joinWarnings(built.Warnings)
		return res
	}
	var xi *xcore.Instance
	if built.Xray != nil {
		setXrayHub(e.Logs)
		if xi, err = startXray(built.Xray); err != nil {
			res.Error = err.Error()
			return res
		}
		defer xi.Close()
	}
	sb, err := startSingBox(built.SingBox, nil, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer sb.Close()

	d := &geo.SOCKS5Dialer{ProxyAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	client := d.HTTPClient(20 * time.Second)
	defer client.CloseIdleConnections()
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tmp.Settings.TestURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		res.Error = e.scrub.Scrub(err.Error())
		return res
	}
	resp.Body.Close()
	res.LatencyMs = max(1, time.Since(start).Milliseconds())
	if info, err := geo.Lookup(ctx, client, e.opts.GeoProviders); err == nil {
		res.IP, res.Country = info.IP, info.Country
		e.geoCache.Put(outboundID, info)
	}
	return res
}

// GeoLookup returns what a profile presents (time zone, coordinates,
// language), looking up the exit IP through the profile's own inbound when
// any value is "auto". Results are cached per (outbound, exit IP); force
// skips the cache.
func (e *Engine) GeoLookup(ctx context.Context, profileID string, force bool) (*geo.Derived, error) {
	e.mu.Lock()
	if e.state == nil {
		e.mu.Unlock()
		return nil, ErrNotRunning
	}
	p := e.state.ProfileByID(profileID)
	var cp config.Profile
	if p != nil {
		cp = *p
	}
	e.mu.Unlock()
	if p == nil {
		return nil, fmt.Errorf("unknown profile %q", profileID)
	}

	ov := geo.Overrides{Timezone: cp.Timezone, Language: cp.Language}
	if !cp.Geo.Auto {
		ov.Geo = &[3]float64{cp.Geo.Lat, cp.Geo.Lon, cp.Geo.AccuracyM}
	}
	needLookup := cp.Timezone == config.Auto || cp.Language == config.Auto || cp.Geo.Auto

	e.geoMu.Lock()
	j, ok := e.jitters[profileID]
	if !ok {
		j = geo.NewJitter()
		e.jitters[profileID] = j
	}
	e.geoMu.Unlock()

	var info *geo.Info
	if needLookup {
		d := &geo.SOCKS5Dialer{ProxyAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(cp.LocalPort))}
		client := d.HTTPClient(25 * time.Second)
		defer client.CloseIdleConnections()
		key := cp.Outbound
		if !force {
			if ip, err := geo.ExitIP(ctx, client); err == nil {
				info, _ = e.geoCache.Get(key, ip)
			}
		}
		if info == nil {
			var err error
			info, err = geo.Lookup(ctx, client, e.opts.GeoProviders)
			if err != nil {
				return nil, fmt.Errorf("geo lookup through profile %s: %s", profileID, e.scrub.Scrub(err.Error()))
			}
			e.geoCache.Put(key, info)
		}
	}
	der := geo.Derive(info, ov, j)
	e.geoMu.Lock()
	e.derived[profileID] = der
	e.geoMu.Unlock()
	return &der, nil
}

// Derived returns the last GeoLookup result for a profile, if any.
func (e *Engine) Derived(profileID string) (geo.Derived, bool) {
	e.geoMu.Lock()
	defer e.geoMu.Unlock()
	d, ok := e.derived[profileID]
	return d, ok
}

// GeoCache exposes the cache for persistence.
func (e *Engine) GeoCache() *geo.Cache { return &e.geoCache }

// --- helpers ---------------------------------------------------------------

func allocXrayInbound(*config.Outbound) (config.XrayInbound, error) {
	port, err := freePort()
	if err != nil {
		return config.XrayInbound{}, err
	}
	return config.XrayInbound{Port: port, User: randHex(8), Pass: randHex(16)}, nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func joinWarnings(w []string) string {
	if len(w) == 0 {
		return "no usable outbound"
	}
	return w[len(w)-1]
}
