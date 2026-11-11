package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"geotunnel/core/config"
	"geotunnel/core/geo"
)

const testUUID = "8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b"

func mustFreePort(t *testing.T) int {
	t.Helper()
	p, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// backend is the "internet": it counts hits and echoes request headers.
func backend(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/geo":
			w.Write([]byte(`{"ip":"203.0.113.77","city":"Istanbul","country":"TR","loc":"41.0138,28.9497","timezone":"Europe/Istanbul"}`))
		case "/ip":
			w.Write([]byte("203.0.113.77"))
		default:
			w.Write([]byte("ok " + r.Header.Get("Accept-Language")))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// startVLESSServer runs an Xray VLESS server (plain TCP) on loopback.
func startVLESSServer(t *testing.T) int {
	t.Helper()
	port := mustFreePort(t)
	cfg := fmt.Sprintf(`{
	  "log": {"loglevel": "warning"},
	  "inbounds": [{"listen": "127.0.0.1", "port": %d, "protocol": "vless",
	    "settings": {"clients": [{"id": %q}], "decryption": "none"},
	    "streamSettings": {"network": "tcp", "security": "none"}}],
	  "outbounds": [{"protocol": "freedom"}]}`, port, testUUID)
	inst, err := startXray([]byte(cfg))
	if err != nil {
		t.Fatalf("vless server: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	return port
}

// startHy2Server runs a sing-box Hysteria2 server with a self-signed cert.
func startHy2Server(t *testing.T) int {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "hy.test"},
		DNSNames: []string{"hy.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kb, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	port := mustFreePort(t)
	cfg := fmt.Sprintf(`{
	  "log": {"level": "warn"},
	  "inbounds": [{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": %d,
	    "users": [{"password": "hy-test-pass"}],
	    "tls": {"enabled": true, "certificate_path": %q, "key_path": %q}}],
	  "outbounds": [{"type": "direct"}]}`, port, certPath, keyPath)
	sb, err := startSingBox([]byte(cfg), nil, nil)
	if err != nil {
		t.Fatalf("hy2 server: %v", err)
	}
	t.Cleanup(func() { sb.Close() })
	return port
}

func get(t *testing.T, proxyPort int, url string, header map[string]string) (string, error) {
	t.Helper()
	d := &geo.SOCKS5Dialer{ProxyAddr: "127.0.0.1:" + strconv.Itoa(proxyPort)}
	c := d.HTTPClient(10 * time.Second)
	defer c.CloseIdleConnections()
	req, _ := http.NewRequest("GET", url, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func stateJSON(t *testing.T, st *config.State) []byte {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEndToEndThroughBothEngines proves the chain
//
//	client -> sing-box mixed inbound -> (socks -> Xray VLESS | native hy2) -> server -> backend
//
// for one Xray-run and one sing-box-run outbound, plus the kill switch for a
// profile whose outbound does not exist.
func TestEndToEndThroughBothEngines(t *testing.T) {
	srv, hits := backend(t)
	vlessPort := startVLESSServer(t)
	hyPort := startHy2Server(t)

	vless, err := config.ParseLink(fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#local-vless", testUUID, vlessPort))
	if err != nil {
		t.Fatal(err)
	}
	hy, err := config.ParseLink(fmt.Sprintf("hy2://hy-test-pass@127.0.0.1:%d/?sni=hy.test&insecure=1#local-hy2", hyPort))
	if err != nil {
		t.Fatal(err)
	}
	pV, pH, pDead := mustFreePort(t), mustFreePort(t), mustFreePort(t)
	st := &config.State{
		Outbounds: []*config.Outbound{vless, hy},
		Profiles: []*config.Profile{
			{ID: "via-xray", Outbound: vless.ID, LocalPort: pV, Timezone: "Europe/Istanbul", Language: "tr-TR",
				Geo: config.GeoSetting{Lat: 41.01, Lon: 28.97, AccuracyM: 1000}},
			{ID: "via-singbox", Outbound: hy.ID, LocalPort: pH},
			{ID: "dead", Outbound: "ob-missing", LocalPort: pDead},
		},
		Settings: config.Settings{Platform: "darwin", LogLevel: "warn"},
	}
	e := New(Options{GeoProviders: []geo.Provider{{Name: "local", URL: srv.URL + "/geo", Parse: geo.DefaultProviders[0].Parse}}})
	if err := e.Start(stateJSON(t, st)); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	for _, port := range []int{pV, pH} {
		before := hits.Load()
		body, err := get(t, port, srv.URL+"/hello", map[string]string{"Accept-Language": "tr-TR,tr;q=0.9"})
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		if !strings.HasPrefix(body, "ok tr-TR") || hits.Load() != before+1 {
			t.Fatalf("port %d: body %q", port, body)
		}
	}
	// Kill switch: the dead profile's inbound accepts but never forwards.
	before := hits.Load()
	if _, err := get(t, pDead, srv.URL+"/hello", nil); err == nil {
		t.Fatal("blocked profile must not reach the backend")
	}
	if hits.Load() != before {
		t.Fatal("blocked profile leaked a request")
	}

	st2 := e.Stats()
	if !st2.Running || st2.ProfileOutbound["dead"] != "" || len(st2.Traffic) == 0 {
		t.Fatalf("stats: %+v", st2)
	}
	var down int64
	for _, tr := range st2.Traffic {
		down += tr.Down
	}
	if down == 0 {
		t.Fatal("traffic counters did not move")
	}

	// GeoLookup through the singbox-run profile ("auto" everything).
	d, err := e.GeoLookup(context.Background(), "via-singbox", false)
	if err != nil {
		t.Fatal(err)
	}
	if d.Country != "TR" || d.Timezone != "Europe/Istanbul" || d.Language != "tr-TR" || d.IP != "203.0.113.77" {
		t.Fatalf("derived: %+v", d)
	}
	if dist := geo.DistanceM(41.0138, 28.9497, d.Lat, d.Lon); dist < 900 || dist > 3100 {
		t.Fatalf("jitter %.0f m out of 1-3 km", dist)
	}
	// Manual profile: no lookup needed, values as configured.
	d2, err := e.GeoLookup(context.Background(), "via-xray", false)
	if err != nil || d2.Lat != 41.01 || d2.Timezone != "Europe/Istanbul" {
		t.Fatalf("manual: %v %+v", err, d2)
	}

	// Logs never carry the credentials.
	for _, l := range e.Logs.Recent() {
		if strings.Contains(l.Msg, testUUID) || strings.Contains(l.Msg, "hy-test-pass") {
			t.Fatalf("credential in log: %s", l.Msg)
		}
	}
	x, s, _ := e.Built()
	if strings.Contains(string(x)+string(s), testUUID) || strings.Contains(string(s), "hy-test-pass") {
		t.Fatal("Built() leaks credentials")
	}

	// Reload with the VLESS profile removed: its port must close.
	st.Profiles = st.Profiles[1:]
	if err := e.Reload(stateJSON(t, st)); err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, pV, srv.URL+"/hello", nil); err == nil {
		t.Fatal("removed profile still serves")
	}
	if _, err := get(t, pH, srv.URL+"/hello", nil); err != nil {
		t.Fatalf("kept profile broke on reload: %v", err)
	}
}

func TestTestOutbound(t *testing.T) {
	srv, _ := backend(t)
	vlessPort := startVLESSServer(t)
	vless, _ := config.ParseLink(fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#v", testUUID, vlessPort))
	st := &config.State{Outbounds: []*config.Outbound{vless}, Settings: config.Settings{TestURL: srv.URL + "/204"}}
	e := New(Options{GeoProviders: []geo.Provider{{Name: "local", URL: srv.URL + "/geo", Parse: geo.DefaultProviders[0].Parse}}})
	r := e.TestOutbound(context.Background(), stateJSON(t, st), vless.ID)
	if r.Error != "" || r.LatencyMs <= 0 || r.Country != "TR" {
		t.Fatalf("%+v", r)
	}
	// Wrong credentials fail cleanly.
	bad, _ := config.ParseLink(fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none&security=none&type=tcp#bad", "00000000-0000-4000-8000-000000000000", vlessPort))
	st.Outbounds = append(st.Outbounds, bad)
	if r := e.TestOutbound(context.Background(), stateJSON(t, st), bad.ID); r.Error == "" {
		t.Fatal("bad credentials should fail")
	}
}
