package geo

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCountryTablesAreValidIANA(t *testing.T) {
	for cc, d := range countryData {
		if _, err := time.LoadLocation(d[1]); err != nil {
			t.Errorf("%s: zone %s: %v", cc, d[1], err)
		}
		if !strings.Contains(d[0], "-") {
			t.Errorf("%s: language %q should be lang-REGION", cc, d[0])
		}
	}
	if CountryLanguage("tr") != "tr-TR" || CountryTimezone("TR") != "Europe/Istanbul" {
		t.Fatal("TR mapping")
	}
}

func TestDerive(t *testing.T) {
	info := &Info{IP: "203.0.113.9", Country: "TR", Timezone: "Europe/Istanbul", Lat: 41.0082, Lon: 28.9784, Provider: "test"}
	j := Jitter{BearingRad: 1, DistanceM: 2000}
	d := Derive(info, Overrides{}, j)
	if d.Timezone != "Europe/Istanbul" || d.Language != "tr-TR" || d.Country != "TR" {
		t.Fatalf("%+v", d)
	}
	dist := DistanceM(info.Lat, info.Lon, d.Lat, d.Lon)
	if dist < 1900 || dist > 2100 {
		t.Fatalf("jitter distance %.0f m, want ~2000", dist)
	}
	if got := strings.Join(d.Languages, ","); got != "tr-TR,tr" {
		t.Fatal(got)
	}
	if AcceptLanguage(d.Languages) != "tr-TR,tr;q=0.9" {
		t.Fatal(AcceptLanguage(d.Languages))
	}
	// Same jitter -> same point (fixed per session).
	if d2 := Derive(info, Overrides{}, j); d2.Lat != d.Lat || d2.Lon != d.Lon {
		t.Fatal("jitter not stable")
	}
	// Manual values win.
	g := [3]float64{39.93, 32.85, 500}
	m := Derive(info, Overrides{Timezone: "Europe/Istanbul", Language: "en-GB", Geo: &g}, j)
	if m.Lat != 39.93 || m.Language != "en-GB" || m.AccuracyM != 500 {
		t.Fatalf("%+v", m)
	}
}

func TestNewJitterRange(t *testing.T) {
	for i := 0; i < 200; i++ {
		j := NewJitter()
		if j.DistanceM < 1000 || j.DistanceM > 3000 {
			t.Fatal(j.DistanceM)
		}
	}
}

func TestCache(t *testing.T) {
	var c Cache
	c.Put("ob-1", &Info{IP: "1.2.3.4", Country: "TR"})
	if _, ok := c.Get("ob-1", "1.2.3.4"); !ok {
		t.Fatal("hit expected")
	}
	if _, ok := c.Get("ob-1", "5.6.7.8"); ok {
		t.Fatal("exit IP change must invalidate")
	}
	c.TTL = time.Nanosecond
	time.Sleep(time.Millisecond)
	if _, ok := c.Get("ob-1", ""); ok {
		t.Fatal("expired entry returned")
	}
	snap := c.Snapshot()
	var c2 Cache
	c2.Load(snap)
	if len(c2.Snapshot()) != 1 {
		t.Fatal("snapshot round trip")
	}
}

// fakeSOCKS is a minimal SOCKS5 server that records the requested host and
// connects to the given backend, so tests can prove remote-DNS semantics.
func fakeSOCKS(t *testing.T, backend string, user, pass string) (addr string, hosts chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	hosts = make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				io.ReadFull(c, buf[:2])
				io.ReadFull(c, buf[:buf[1]])
				if user != "" {
					c.Write([]byte{5, 2})
					io.ReadFull(c, buf[:2])
					u := make([]byte, buf[1])
					io.ReadFull(c, u)
					io.ReadFull(c, buf[:1])
					p := make([]byte, buf[0])
					io.ReadFull(c, p)
					if string(u) != user || string(p) != pass {
						c.Write([]byte{1, 1})
						return
					}
					c.Write([]byte{1, 0})
				} else {
					c.Write([]byte{5, 0})
				}
				io.ReadFull(c, buf[:4])
				var host string
				switch buf[3] {
				case 3:
					io.ReadFull(c, buf[:1])
					h := make([]byte, buf[0])
					io.ReadFull(c, h)
					host = string(h)
				case 1:
					io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				}
				io.ReadFull(c, buf[:2])
				hosts <- host + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(buf[:2])))
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
	return ln.Addr().String(), hosts
}

func TestLookupThroughSOCKSWithFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/broken":
			http.Error(w, "nope", http.StatusServiceUnavailable)
		case "/ipinfo":
			w.Write([]byte(`{"ip":"203.0.113.77","city":"Istanbul","region":"Istanbul","country":"TR","loc":"41.0138,28.9497","org":"AS0 Example","timezone":"Europe/Istanbul"}`))
		}
	}))
	defer srv.Close()
	addr, hosts := fakeSOCKS(t, srv.Listener.Addr().String(), "u", "p")
	d := &SOCKS5Dialer{ProxyAddr: addr, User: "u", Pass: "p"}
	client := d.HTTPClient(10 * time.Second)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	providers := []Provider{
		{Name: "broken", URL: "http://geo-a.invalid:" + strconv.Itoa(port) + "/broken", Parse: parseIPInfo},
		{Name: "ipinfo", URL: "http://geo-b.invalid:" + strconv.Itoa(port) + "/ipinfo", Parse: parseIPInfo},
	}
	info, err := Lookup(context.Background(), client, providers)
	if err != nil {
		t.Fatal(err)
	}
	if info.Provider != "ipinfo" || info.Country != "TR" || info.Timezone != "Europe/Istanbul" || info.Lat != 41.0138 {
		t.Fatalf("%+v", info)
	}
	// The hostname reached the proxy unresolved (".invalid" cannot resolve
	// locally), i.e. DNS happened on the remote side.
	got := <-hosts
	if !strings.HasPrefix(got, "geo-a.invalid:") {
		t.Fatalf("proxy saw %q, want the unresolved hostname", got)
	}
}

func TestProviderParsers(t *testing.T) {
	w, err := parseIPWhois([]byte(`{"ip":"203.0.113.5","success":true,"country":"Turkey","country_code":"TR","latitude":41.0,"longitude":29.0,"timezone":{"id":"Europe/Istanbul"},"connection":{"org":"X"}}`))
	if err != nil || w.Country != "TR" || w.Timezone != "Europe/Istanbul" {
		t.Fatalf("%v %+v", err, w)
	}
	a, err := parseIPAPI([]byte(`{"status":"success","country":"Germany","countryCode":"DE","regionName":"Hesse","city":"Frankfurt","lat":50.11,"lon":8.68,"timezone":"Europe/Berlin","org":"Y","query":"198.51.100.1"}`))
	if err != nil || a.IP != "198.51.100.1" || a.Country != "DE" {
		t.Fatalf("%v %+v", err, a)
	}
	if _, err := parseIPAPI([]byte(`{"status":"fail","message":"reserved range"}`)); err == nil {
		t.Fatal("fail status must error")
	}
}
