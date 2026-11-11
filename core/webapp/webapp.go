// Package webapp runs a web app inside GeoTunnel's desktop container: a
// Chromium-family browser with an isolated profile, the profile's SOCKS
// inbound as its only network path, and CDP overrides for time zone, locale,
// geolocation and Accept-Language applied to every target (pages, popups,
// iframes, workers) before any of its scripts run.
package webapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"geotunnel/core/desktop"
	"geotunnel/core/geo"
)

// Options configure one container window.
type Options struct {
	URL         string
	ProxyPort   int // profile's local SOCKS5 port; 0 only in tests
	Timezone    string
	Locale      string   // e.g. tr-TR
	Languages   []string // default derived from Locale
	Lat, Lon    float64
	AccuracyM   float64
	WebRTC      string // "disable" (default) | "proxy-only"
	UserDataDir string // one per web app: cookies, storage, service workers
	Browser     string
	Headless    bool
	// UseDebugPort forces the WebSocket transport (the Windows code path).
	UseDebugPort bool
	// ProxyLoopback sends loopback traffic through the proxy too (tests).
	ProxyLoopback bool
	// NoProcessEnv skips setting TZ/LANG on the browser process, leaving
	// CDP as the only override (tests use it to prove the CDP path).
	NoProcessEnv bool
	ExtraArgs    []string
	OnEvent      func(Event)
}

// Event is emitted for UI/log purposes.
type Event struct {
	Type     string `json:"type"` // ready | target | warning | exit
	TargetID string `json:"targetId,omitempty"`
	Kind     string `json:"kind,omitempty"`
	URL      string `json:"url,omitempty"`
	Message  string `json:"message,omitempty"`
}

// Session is a running container.
type Session struct {
	opts   Options
	cmd    *exec.Cmd
	conn   *Conn
	ua     string
	mainMu sync.Mutex
	main   string // session id of the first page
	mainCh chan struct{}
	done   chan struct{}
}

// Args returns the browser command line for o (exported for tests/docs).
func Args(o Options) []string {
	langs := o.Languages
	if len(langs) == 0 && o.Locale != "" {
		langs = geo.LanguageList(o.Locale)
	}
	args := []string{
		"--user-data-dir=" + o.UserDataDir,
		"--no-first-run", "--no-default-browser-check", "--disable-sync",
		"--disable-background-networking", "--disable-component-update",
		"--disable-features=Translate,MediaRouter,OptimizationHints,AutofillServerCommunication",
		// Only proxied UDP may be used by WebRTC; with a SOCKS proxy that
		// means no UDP at all, so the real IP never appears in candidates.
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
	}
	if o.ProxyPort > 0 {
		args = append(args,
			"--proxy-server=socks5://127.0.0.1:"+strconv.Itoa(o.ProxyPort),
			// Nothing may be resolved locally: names go to the proxy.
			"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		)
		if o.ProxyLoopback {
			args = append(args, "--proxy-bypass-list=<-loopback>")
		}
	}
	if o.Locale != "" {
		args = append(args, "--lang="+o.Locale, "--accept-lang="+strings.Join(langs, ","))
	}
	if o.UseDebugPort {
		args = append(args, "--remote-debugging-port=0")
	} else {
		args = append(args, "--remote-debugging-pipe")
	}
	if o.Headless {
		args = append(args, "--headless=new", "--disable-gpu")
	}
	args = append(args, o.ExtraArgs...)
	if o.Headless {
		args = append(args, "about:blank")
	} else {
		args = append(args, "--app=about:blank")
	}
	return args
}

// Launch starts the browser and wires the overrides.
func Launch(ctx context.Context, o Options) (*Session, error) {
	if o.URL == "" {
		return nil, errors.New("webapp: URL required")
	}
	if o.UserDataDir == "" {
		return nil, errors.New("webapp: UserDataDir required (one isolated profile per web app)")
	}
	if o.WebRTC == "" {
		o.WebRTC = "disable"
	}
	if o.AccuracyM == 0 {
		o.AccuracyM = 3000
	}
	if o.Browser == "" {
		b, err := FindBrowser()
		if err != nil {
			return nil, err
		}
		o.Browser = b
	}
	if err := os.MkdirAll(o.UserDataDir, 0o700); err != nil {
		return nil, err
	}
	cmd := exec.Command(o.Browser, Args(o)...)
	env := os.Environ()
	if !o.NoProcessEnv {
		env = desktop.Env(env, desktop.LaunchOptions{Timezone: o.Timezone, Locale: o.Locale})
	}
	cmd.Env = env
	s := &Session{opts: o, cmd: cmd, mainCh: make(chan struct{}), done: make(chan struct{})}

	tr, err := startWithTransport(ctx, cmd, o)
	if err != nil {
		return nil, err
	}
	s.conn = newConn(tr, s.onEvent)
	go func() {
		cmd.Wait()
		tr.Close()
		s.emit(Event{Type: "exit"})
		close(s.done)
	}()

	if err := s.setup(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Session) emit(ev Event) {
	if s.opts.OnEvent != nil {
		s.opts.OnEvent(ev)
	}
}

func (s *Session) setup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ver, err := s.conn.Call(ctx, "", "Browser.getVersion", nil)
	if err != nil {
		return fmt.Errorf("webapp: browser did not answer CDP: %w", err)
	}
	var v struct{ UserAgent string }
	json.Unmarshal(ver, &v)
	// Headless builds announce themselves in the UA; present a normal one.
	s.ua = strings.Replace(v.UserAgent, "HeadlessChrome", "Chrome", 1)

	if _, err := s.conn.Call(ctx, "", "Browser.grantPermissions", map[string]any{"permissions": []string{"geolocation"}}); err != nil {
		s.emit(Event{Type: "warning", Message: err.Error()})
	}
	if _, err := s.conn.Call(ctx, "", "Target.setDiscoverTargets", map[string]any{"discover": true}); err != nil {
		return err
	}
	// Attach to every existing and future target and hold new ones until
	// configured.
	if _, err := s.conn.Call(ctx, "", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
	}); err != nil {
		return err
	}
	select {
	case <-s.mainCh:
	case <-ctx.Done():
		return errors.New("webapp: no page target appeared")
	}
	_, err = s.conn.Call(ctx, s.mainSession(), "Page.navigate", map[string]any{"url": s.opts.URL})
	return err
}

func (s *Session) mainSession() string {
	s.mainMu.Lock()
	defer s.mainMu.Unlock()
	return s.main
}

func (s *Session) onEvent(sessionID, method string, params json.RawMessage) {
	if method != "Target.attachedToTarget" {
		return
	}
	var p struct {
		SessionID  string `json:"sessionId"`
		TargetInfo struct {
			TargetID string `json:"targetId"`
			Type     string `json:"type"`
			URL      string `json:"url"`
		} `json:"targetInfo"`
		WaitingForDebugger bool `json:"waitingForDebugger"`
	}
	if json.Unmarshal(params, &p) != nil {
		return
	}
	// Never block the read loop: configure in a goroutine.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		s.configure(ctx, p.SessionID, p.TargetInfo.Type)
		if p.WaitingForDebugger {
			s.conn.Call(ctx, p.SessionID, "Runtime.runIfWaitingForDebugger", nil)
		}
		s.emit(Event{Type: "target", TargetID: p.TargetInfo.TargetID, Kind: p.TargetInfo.Type, URL: p.TargetInfo.URL})
		if p.TargetInfo.Type == "page" {
			s.mainMu.Lock()
			if s.main == "" {
				s.main = p.SessionID
				close(s.mainCh)
			}
			s.mainMu.Unlock()
		}
	}()
}

// webrtcOff removes WebRTC entirely ("disable" mode). Chrome's IP-handling
// policy already keeps the real IP out of candidates; this also stops pages
// from fingerprinting the WebRTC stack.
const webrtcOff = `(() => {
  for (const k of ['RTCPeerConnection','webkitRTCPeerConnection','RTCDataChannel','RTCIceCandidate','RTCSessionDescription','RTCRtpSender','RTCRtpReceiver','RTCRtpTransceiver','RTCDtlsTransport','RTCIceTransport','RTCSctpTransport','RTCCertificate','RTCError','RTCErrorEvent','RTCTrackEvent','RTCDataChannelEvent','RTCPeerConnectionIceEvent','RTCPeerConnectionIceErrorEvent','RTCStatsReport','RTCDTMFSender','RTCDTMFToneChangeEvent','RTCEncodedAudioFrame','RTCEncodedVideoFrame']) {
    try { delete globalThis[k]; } catch (e) {}
  }
  try { if (navigator.mediaDevices) { Object.defineProperty(MediaDevices.prototype, 'getUserMedia', {value: undefined}); } } catch (e) {}
})();`

func (s *Session) configure(ctx context.Context, sid, kind string) {
	o := s.opts
	langs := o.Languages
	if len(langs) == 0 && o.Locale != "" {
		langs = geo.LanguageList(o.Locale)
	}
	call := func(method string, params any) {
		if _, err := s.conn.Call(ctx, sid, method, params); err != nil {
			// Workers lack some domains; that is expected and harmless.
			if kind == "page" || kind == "iframe" {
				s.emit(Event{Type: "warning", Message: kind + " " + method + ": " + err.Error()})
			}
		}
	}
	if o.Timezone != "" {
		call("Emulation.setTimezoneOverride", map[string]any{"timezoneId": o.Timezone})
	}
	if o.Locale != "" {
		call("Emulation.setLocaleOverride", map[string]any{"locale": o.Locale})
		// CDP appends q-values itself ("ja-JP,ja" -> "ja-JP,ja;q=0.9") and
		// derives navigator.languages from the same list.
		ua := map[string]any{"userAgent": s.ua, "acceptLanguage": strings.Join(langs, ",")}
		call("Network.setUserAgentOverride", ua)
		if kind == "page" || kind == "iframe" {
			call("Emulation.setUserAgentOverride", ua)
		}
	}
	if kind == "page" || kind == "iframe" {
		call("Emulation.setGeolocationOverride", map[string]any{"latitude": o.Lat, "longitude": o.Lon, "accuracy": o.AccuracyM})
		if o.WebRTC == "disable" {
			call("Page.enable", nil)
			call("Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": webrtcOff, "runImmediately": true})
		}
	}
	// Catch this target's own children (dedicated workers, OOPIFs).
	call("Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true})
}

// Evaluate runs an expression in the main page and returns its JSON value.
func (s *Session) Evaluate(ctx context.Context, expr string) (json.RawMessage, error) {
	res, err := s.conn.Call(ctx, s.mainSession(), "Runtime.evaluate", map[string]any{
		"expression": expr, "awaitPromise": true, "returnByValue": true,
	})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, err
	}
	if r.ExceptionDetails != nil {
		return nil, fmt.Errorf("page exception: %s %s", r.ExceptionDetails.Text, r.ExceptionDetails.Exception.Description)
	}
	return r.Result.Value, nil
}

// WaitLoad waits until the main document finished loading.
func (s *Session) WaitLoad(ctx context.Context) error {
	for {
		v, err := s.Evaluate(ctx, `document.readyState === 'complete' && location.href !== 'about:blank'`)
		if err == nil && string(v) == "true" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Done is closed when the browser exits.
func (s *Session) Done() <-chan struct{} { return s.done }

// Close asks the browser to quit, then kills it if needed.
func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.conn.Call(ctx, "", "Browser.close", nil)
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		if s.cmd.Process != nil {
			s.cmd.Process.Kill()
		}
		<-s.done
	}
	return nil
}
