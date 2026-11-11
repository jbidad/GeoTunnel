package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"geotunnel/core/geo"
)

// Check is one line of the leak-test checklist.
type Check struct {
	Name     string `json:"name"` // exit-ip, dns, ipv6, timezone, language, geolocation, webrtc
	Pass     bool   `json:"pass"`
	Skipped  bool   `json:"skipped,omitempty"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
	Detail   string `json:"detail,omitempty"` // the mismatch, in words
}

// LeakReport is the full result for one profile.
type LeakReport struct {
	ProfileID string      `json:"profileId"`
	Expected  geo.Derived `json:"expected"`
	Checks    []Check     `json:"checks"`
	Pass      bool        `json:"pass"`
	RanAt     time.Time   `json:"ranAt"`
}

// Finish computes the overall verdict.
func (r *LeakReport) Finish() {
	r.Pass = true
	for _, c := range r.Checks {
		if !c.Pass && !c.Skipped {
			r.Pass = false
		}
	}
	r.RanAt = time.Now()
}

// LeakOptions tune the network checks.
type LeakOptions struct {
	// CompareDirect also fetches the real (untunneled) IPv4/IPv6 so the
	// report can prove they don't show up. This makes direct requests to the
	// IP-echo services.
	CompareDirect bool
	// DNSLeakAPI is a bash.ws-compatible service (default https://bash.ws).
	DNSLeakAPI string
}

// RealIPs are the user's untunneled addresses (when CompareDirect is on).
type RealIPs struct {
	V4, V6, Country string
}

// LeakTestNetwork runs the checks that live below the browser: exit IP and
// country, DNS resolvers, IPv6 — all through the profile's own inbound, i.e.
// the same outbound and DNS path its apps use.
func (e *Engine) LeakTestNetwork(ctx context.Context, profileID string, opts LeakOptions) (*LeakReport, *RealIPs, error) {
	port, err := e.ProfilePort(profileID)
	if err != nil {
		return nil, nil, err
	}
	expected, err := e.GeoLookup(ctx, profileID, true)
	if err != nil {
		return nil, nil, err
	}
	rep := &LeakReport{ProfileID: profileID, Expected: *expected}
	d := &geo.SOCKS5Dialer{ProxyAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	tunneled := d.HTTPClient(25 * time.Second)
	defer tunneled.CloseIdleConnections()

	var real *RealIPs
	if opts.CompareDirect {
		direct := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}}
		real = &RealIPs{}
		real.V4, _ = fetchString(ctx, direct, "https://api.ipify.org")
		real.V6, _ = fetchString(ctx, direct, "https://api6.ipify.org")
		if info, err := geo.Lookup(ctx, direct, e.opts.GeoProviders); err == nil {
			real.Country = info.Country
		}
	}

	// Exit IP.
	exit := Check{Name: "exit-ip", Expected: expected.Country, Observed: expected.IP + " (" + expected.Country + ")"}
	switch {
	case expected.IP == "":
		exit.Detail = "exit IP lookup failed"
	case real != nil && real.V4 != "" && real.V4 == expected.IP:
		exit.Detail = "exit IP equals your real IP: the profile is not tunneled"
	default:
		exit.Pass = true
	}
	rep.Checks = append(rep.Checks, exit)

	// DNS resolvers.
	rep.Checks = append(rep.Checks, e.dnsCheck(ctx, d, tunneled, expected.Country, real, opts.DNSLeakAPI))

	// IPv6.
	v6 := Check{Name: "ipv6"}
	if ip, err := fetchString(ctx, tunneled, "https://api6.ipify.org"); err == nil && strings.Contains(ip, ":") {
		v6.Observed = ip
		v6.Pass = real == nil || real.V6 == "" || real.V6 != ip
		if !v6.Pass {
			v6.Detail = "IPv6 traffic exits with your real IPv6 address"
		}
	} else {
		v6.Pass = true
		v6.Observed = "no IPv6 through the tunnel"
		if real != nil && real.V6 != "" {
			v6.Detail = "you have IPv6 (" + real.V6 + ") but tunneled apps cannot reach IPv6-only hosts; nothing leaks"
		}
	}
	rep.Checks = append(rep.Checks, v6)
	return rep, real, nil
}

type dnsLeakEntry struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
	ASN         string `json:"asn"`
	Type        string `json:"type"` // ip | dns | conclusion
}

func (e *Engine) dnsCheck(ctx context.Context, d *geo.SOCKS5Dialer, client *http.Client, exitCountry string, real *RealIPs, api string) Check {
	c := Check{Name: "dns", Expected: exitCountry}
	if api == "" {
		api = "https://bash.ws"
	}
	id, err := fetchString(ctx, client, api+"/id")
	if err != nil || id == "" {
		c.Skipped = true
		c.Detail = "DNS leak service unreachable through the tunnel"
		return c
	}
	host := strings.TrimPrefix(strings.TrimPrefix(api, "https://"), "http://")
	for i := 1; i <= 5; i++ {
		// Connecting by name makes the far side resolve it; the connect
		// itself is expected to fail.
		cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		if conn, err := d.DialContext(cctx, "tcp", fmt.Sprintf("%d.%s.%s:80", i, id, host)); err == nil {
			conn.Close()
		}
		cancel()
	}
	body, err := fetchString(ctx, client, api+"/dnsleak/test/"+id+"?json")
	if err != nil {
		c.Skipped = true
		c.Detail = "DNS leak result unavailable"
		return c
	}
	var entries []dnsLeakEntry
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		c.Skipped = true
		c.Detail = "DNS leak result unreadable"
		return c
	}
	var resolvers []string
	countries := map[string]bool{}
	for _, en := range entries {
		if en.Type != "dns" {
			continue
		}
		cc := strings.ToUpper(en.Country)
		resolvers = append(resolvers, en.IP+" ("+cc+")")
		countries[cc] = true
	}
	c.Observed = strings.Join(resolvers, ", ")
	if len(resolvers) == 0 {
		c.Skipped = true
		c.Detail = "no resolver was observed"
		return c
	}
	c.Pass = true
	var others []string
	for cc := range countries {
		if cc != exitCountry {
			others = append(others, cc)
		}
	}
	if real != nil && real.Country != "" && countries[real.Country] && real.Country != exitCountry {
		c.Pass = false
		c.Detail = fmt.Sprintf("IP: %s, DNS: %s — a resolver in your real country answered", exitCountry, real.Country)
	} else if len(others) > 0 {
		c.Pass = false
		c.Detail = fmt.Sprintf("IP: %s, DNS: %s", exitCountry, strings.Join(others, "/"))
	}
	return c
}

func fetchString(ctx context.Context, c *http.Client, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return strings.TrimSpace(string(b)), nil
}

// BrowserObserved is what webinject/leakprobe.js reports from inside a
// container page.
type BrowserObserved struct {
	Timezone       string   `json:"timezone"`
	OffsetMin      int      `json:"offsetMin"` // -Date.prototype.getTimezoneOffset()
	DateString     string   `json:"dateString"`
	IntlLocale     string   `json:"intlLocale"`
	Language       string   `json:"language"`
	Languages      []string `json:"languages"`
	AcceptLanguage string   `json:"acceptLanguage"` // as echoed by a server
	Geo            *struct {
		Lat      float64 `json:"lat"`
		Lon      float64 `json:"lon"`
		Accuracy float64 `json:"accuracy"`
		Error    string  `json:"error"`
	} `json:"geo"`
	WebRTC struct {
		Available  bool     `json:"available"`
		Candidates []string `json:"candidates"` // candidate addresses
		Error      string   `json:"error"`
	} `json:"webrtc"`
}

// EvaluateBrowser turns probe observations into checks against what the
// profile should present. realIPs (optional) are the user's untunneled
// addresses.
func EvaluateBrowser(exp geo.Derived, obs BrowserObserved, real *RealIPs) []Check {
	var out []Check
	now := time.Now()

	tz := Check{Name: "timezone", Expected: exp.Timezone, Observed: obs.Timezone}
	if loc, err := time.LoadLocation(exp.Timezone); err == nil {
		_, off := now.In(loc).Zone()
		wantMin := off / 60
		tz.Pass = obs.Timezone == exp.Timezone && obs.OffsetMin == wantMin
		if !tz.Pass {
			tz.Detail = fmt.Sprintf("page sees %s (UTC%+d min), profile expects %s (UTC%+d min)", obs.Timezone, obs.OffsetMin, exp.Timezone, wantMin)
		}
		if tz.Pass && obs.DateString != "" && !strings.Contains(obs.DateString, gmtOffset(wantMin)) {
			tz.Pass = false
			tz.Detail = "Date.prototype.toString shows " + obs.DateString
		}
	}
	out = append(out, tz)

	lang := Check{Name: "language", Expected: exp.Language, Observed: obs.Language}
	lang.Pass = strings.EqualFold(obs.Language, exp.Language) &&
		(len(obs.Languages) == 0 || strings.EqualFold(obs.Languages[0], exp.Language))
	if obs.AcceptLanguage != "" && !strings.HasPrefix(strings.ToLower(obs.AcceptLanguage), strings.ToLower(exp.Language)) {
		lang.Pass = false
		lang.Detail = "Accept-Language header is " + obs.AcceptLanguage
	}
	if obs.IntlLocale != "" && !strings.EqualFold(obs.IntlLocale, exp.Language) {
		lang.Pass = false
		lang.Detail = strings.TrimSpace(lang.Detail + " Intl default locale is " + obs.IntlLocale)
	}
	if !lang.Pass && lang.Detail == "" {
		lang.Detail = fmt.Sprintf("navigator.language=%s languages=%v", obs.Language, obs.Languages)
	}
	out = append(out, lang)

	g := Check{Name: "geolocation", Expected: fmt.Sprintf("%.4f,%.4f ±%.0fm", exp.Lat, exp.Lon, exp.AccuracyM)}
	switch {
	case obs.Geo == nil:
		g.Skipped = true
		g.Detail = "geolocation not probed"
	case obs.Geo.Error != "":
		g.Observed = "error: " + obs.Geo.Error
		g.Detail = "page could not read a position"
	default:
		dist := geo.DistanceM(exp.Lat, exp.Lon, obs.Geo.Lat, obs.Geo.Lon)
		g.Observed = fmt.Sprintf("%.4f,%.4f (%.0f m away)", obs.Geo.Lat, obs.Geo.Lon, dist)
		g.Pass = dist <= math.Max(exp.AccuracyM, 5000)
		if !g.Pass {
			g.Detail = fmt.Sprintf("reported position is %.1f km from the profile's location", dist/1000)
		}
	}
	out = append(out, g)

	w := Check{Name: "webrtc", Observed: strings.Join(obs.WebRTC.Candidates, ", ")}
	if !obs.WebRTC.Available {
		w.Pass = true
		w.Observed = "WebRTC disabled"
	} else {
		w.Pass = true
		var bad []string
		for _, c := range obs.WebRTC.Candidates {
			if strings.HasSuffix(c, ".local") {
				continue // mDNS-obfuscated host candidate
			}
			ip := net.ParseIP(c)
			if ip == nil || c == exp.IP {
				continue
			}
			if real != nil && (c == real.V4 || c == real.V6) {
				bad = append([]string{c + " (your real IP)"}, bad...)
				continue
			}
			bad = append(bad, c)
		}
		if len(bad) > 0 {
			w.Pass = false
			w.Detail = "WebRTC exposes " + strings.Join(bad, ", ")
		}
	}
	out = append(out, w)
	return out
}

func gmtOffset(min int) string {
	sign := "+"
	if min < 0 {
		sign = "-"
		min = -min
	}
	return fmt.Sprintf("GMT%s%02d%02d", sign, min/60, min%60)
}
