package webapp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"geotunnel/core/engine"
	"geotunnel/core/geo"
)

// socksRecorder is a tiny SOCKS5 CONNECT proxy that records requested
// hosts and sends every connection to one backend.
type socksRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (s *socksRecorder) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hosts...)
}

func startSOCKS(t *testing.T, backend string) (int, *socksRecorder) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	rec := &socksRecorder{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 262)
				if _, err := io.ReadFull(c, b[:2]); err != nil {
					return
				}
				io.ReadFull(c, b[:b[1]])
				c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, b[:4]); err != nil {
					return
				}
				host := ""
				switch b[3] {
				case 1:
					io.ReadFull(c, b[:4])
					host = net.IP(b[:4]).String()
				case 3:
					io.ReadFull(c, b[:1])
					h := make([]byte, b[0])
					io.ReadFull(c, h)
					host = string(h)
				case 4:
					io.ReadFull(c, b[:16])
					host = net.IP(b[:16]).String()
				}
				io.ReadFull(c, b[:2])
				port := binary.BigEndian.Uint16(b[:2])
				rec.mu.Lock()
				rec.hosts = append(rec.hosts, host+":"+strconv.Itoa(int(port)))
				rec.mu.Unlock()
				up, err := net.Dial("tcp", backend)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, rec
}

const testPage = `<!doctype html><html><head><title>probe</title></head><body>probe</body></html>`

const workerJS = `postMessage({tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
  offset: new Date().getTimezoneOffset(), lang: navigator.language, langs: navigator.languages});`

// probe gathers everything the leak test looks at, from inside the page.
const probe = `(async () => {
  const r = {};
  r.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  r.offset = new Date().getTimezoneOffset();
  r.dateString = new Date().toString();
  r.intlLocale = Intl.NumberFormat().resolvedOptions().locale;
  r.lang = navigator.language;
  r.langs = navigator.languages;
  r.headers = await (await fetch('/headers')).json();
  r.geo = await new Promise(res => navigator.geolocation.getCurrentPosition(
    p => res({lat: p.coords.latitude, lon: p.coords.longitude, acc: p.coords.accuracy}),
    e => res({error: e.message}), {timeout: 5000}));
  r.worker = await new Promise(res => { const w = new Worker('/worker.js'); w.onmessage = e => res(e.data); w.onerror = e => res({error: String(e.message)}); });
  r.rtc = typeof RTCPeerConnection;
  if (typeof RTCPeerConnection !== 'undefined') {
    r.candidates = await new Promise(res => {
      const out = [];
      const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
      pc.createDataChannel('x');
      pc.onicecandidate = e => { if (e.candidate) out.push(e.candidate.candidate); else res(out); };
      pc.createOffer().then(o => pc.setLocalDescription(o));
      setTimeout(() => res(out), 4000);
    });
  }
  return r;
})()`

type probeResult struct {
	TZ         string            `json:"tz"`
	Offset     int               `json:"offset"`
	DateString string            `json:"dateString"`
	IntlLocale string            `json:"intlLocale"`
	Lang       string            `json:"lang"`
	Langs      []string          `json:"langs"`
	Headers    map[string]string `json:"headers"`
	Geo        struct {
		Lat, Lon, Acc float64
		Error         string
	} `json:"geo"`
	Worker struct {
		TZ     string   `json:"tz"`
		Offset int      `json:"offset"`
		Lang   string   `json:"lang"`
		Langs  []string `json:"langs"`
		Error  string   `json:"error"`
	} `json:"worker"`
	RTC        string   `json:"rtc"`
	Candidates []string `json:"candidates"`
}

func runProbe(t *testing.T, o Options) (probeResult, *socksRecorder) {
	t.Helper()
	var r probeResult
	rec := runInContainer(t, o, probe, &r)
	return r, rec
}

func runInContainer(t *testing.T, o Options, expr string, out any) *socksRecorder {
	t.Helper()
	browser, err := FindBrowser()
	if err != nil {
		t.Skip("no Chromium-family browser installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/headers":
			json.NewEncoder(w).Encode(map[string]string{"accept-language": r.Header.Get("Accept-Language"), "user-agent": r.UserAgent()})
		case "/echo":
			w.Header().Set("Access-Control-Allow-Origin", "*")
			json.NewEncoder(w).Encode(map[string]any{"headers": map[string]string{"Accept-Language": r.Header.Get("Accept-Language")}})
		case "/worker.js":
			w.Header().Set("Content-Type", "text/javascript")
			w.Write([]byte(workerJS))
		default:
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(testPage))
		}
	}))
	t.Cleanup(srv.Close)
	port, rec := startSOCKS(t, srv.Listener.Addr().String())
	backendPort := srv.Listener.Addr().(*net.TCPAddr).Port

	o.Browser = browser
	o.Headless = true
	o.ProxyPort = port
	o.ProxyLoopback = true
	o.NoProcessEnv = true // prove the CDP overrides alone are enough
	// Not t.TempDir: on Windows the browser can hold profile files for a
	// moment after exit, which would fail the test during cleanup.
	dir, err := os.MkdirTemp("", "gt-webapp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	o.UserDataDir = dir
	if runtime.GOOS == "windows" {
		o.UseDebugPort = true // pipes cannot be inherited on Windows
	}
	// CI hook, e.g. "--no-sandbox" where the runner forbids Chrome's sandbox.
	o.ExtraArgs = append(o.ExtraArgs, strings.Fields(os.Getenv("GEOTUNNEL_TEST_BROWSER_ARGS"))...)
	// A name that cannot resolve locally: it only works if the proxy resolves it.
	o.URL = "http://geotunnel-test.example:" + strconv.Itoa(backendPort) + "/"
	// Real web apps are https; the plain-http test origin needs this for
	// navigator.geolocation (secure contexts only).
	o.ExtraArgs = append(o.ExtraArgs, "--unsafely-treat-insecure-origin-as-secure="+strings.TrimSuffix(o.URL, "/"))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s, err := Launch(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.WaitLoad(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(expr, "__ORIGIN__") {
		expr = strings.ReplaceAll(expr, "__ORIGIN__", strings.TrimSuffix(o.URL, "/"))
	}
	v, err := s.Evaluate(ctx, expr)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(v, out); err != nil {
		t.Fatalf("%v: %s", err, v)
	}
	return rec
}

// TestLeakProbeAgainstEvaluator runs the shipped read-only probe in the
// container and scores it with the engine's evaluator: the desktop leak
// test path end to end (minus the network part, covered in engine tests).
func TestLeakProbeAgainstEvaluator(t *testing.T) {
	var obs engine.BrowserObserved
	o := Options{Timezone: "Europe/Istanbul", Locale: "tr-TR", Lat: 41.0082, Lon: 28.9784, AccuracyM: 2000, WebRTC: "disable"}
	runInContainer(t, o, LeakProbe("__ORIGIN__/echo"), &obs)
	exp := geo.Derived{Timezone: "Europe/Istanbul", Language: "tr-TR", Languages: []string{"tr-TR", "tr"}, Lat: 41.0082, Lon: 28.9784, AccuracyM: 2000}
	for _, c := range engine.EvaluateBrowser(exp, obs, nil) {
		if !c.Pass {
			t.Errorf("%s failed: expected %q observed %q: %s", c.Name, c.Expected, c.Observed, c.Detail)
		}
	}
	if obs.AcceptLanguage == "" {
		t.Errorf("probe did not read the echoed Accept-Language: %+v", obs)
	}
}

func TestContainerOverrides(t *testing.T) {
	r, rec := runProbe(t, Options{Timezone: "Asia/Tokyo", Locale: "ja-JP", Lat: 35.6812, Lon: 139.7671, AccuracyM: 1500, WebRTC: "disable"})
	t.Logf("probe: %+v", r)
	if r.TZ != "Asia/Tokyo" || r.Offset != -540 || !strings.Contains(r.DateString, "GMT+0900") {
		t.Errorf("time zone not overridden: tz=%s offset=%d date=%s", r.TZ, r.Offset, r.DateString)
	}
	if r.Lang != "ja-JP" || strings.Join(r.Langs, ",") != "ja-JP,ja" {
		t.Errorf("navigator.language(s) = %s %v", r.Lang, r.Langs)
	}
	if !strings.HasPrefix(r.Headers["accept-language"], "ja-JP") {
		t.Errorf("Accept-Language = %q", r.Headers["accept-language"])
	}
	if strings.Contains(r.Headers["user-agent"], "Headless") {
		t.Errorf("UA reveals headless: %s", r.Headers["user-agent"])
	}
	if r.IntlLocale != "ja-JP" {
		t.Errorf("Intl default locale = %s", r.IntlLocale)
	}
	if r.Geo.Error != "" || r.Geo.Lat != 35.6812 || r.Geo.Lon != 139.7671 {
		t.Errorf("geolocation = %+v", r.Geo)
	}
	if r.Worker.Error != "" || r.Worker.TZ != "Asia/Tokyo" || r.Worker.Offset != -540 || r.Worker.Lang != "ja-JP" {
		t.Errorf("dedicated worker sees %+v", r.Worker)
	}
	if r.RTC != "undefined" {
		t.Errorf("WebRTC should be removed in disable mode, typeof = %s", r.RTC)
	}
	sawName := false
	for _, h := range rec.seen() {
		if strings.HasPrefix(h, "geotunnel-test.example:") {
			sawName = true
		}
	}
	if !sawName {
		t.Errorf("proxy never saw the unresolved hostname: %v", rec.seen())
	}
}

func TestContainerWebRTCProxyOnly(t *testing.T) {
	r, _ := runProbe(t, Options{Timezone: "Europe/Istanbul", Locale: "tr-TR", Lat: 41.0, Lon: 29.0, WebRTC: "proxy-only"})
	if r.RTC != "function" {
		t.Fatalf("WebRTC should exist in proxy-only mode, typeof = %s", r.RTC)
	}
	for _, c := range r.Candidates {
		// candidate:<foundation> <component> <proto> <prio> <address> <port> typ <type>
		f := strings.Fields(c)
		if len(f) > 4 && !strings.HasSuffix(f[4], ".local") && net.ParseIP(f[4]) != nil {
			t.Errorf("WebRTC exposed an address: %s", c)
		}
	}
	t.Logf("candidates: %v", r.Candidates)
}

func TestDebugPortTransport(t *testing.T) {
	r, _ := runProbe(t, Options{Timezone: "America/New_York", Locale: "en-US", Lat: 40.7, Lon: -74.0, UseDebugPort: true})
	if r.TZ != "America/New_York" {
		t.Fatalf("websocket transport: tz=%s", r.TZ)
	}
}
