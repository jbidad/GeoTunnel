package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ErrUnsupportedScheme is returned for share links GeoTunnel cannot import.
var ErrUnsupportedScheme = errors.New("unsupported share link scheme")

// ParseLink parses one share link (vless://, vmess://, trojan://, ss://,
// hysteria2:// / hy2://, tuic://) into an Outbound with a stable ID.
func ParseLink(link string) (*Outbound, error) {
	link = strings.TrimSpace(link)
	scheme, _, ok := strings.Cut(link, "://")
	if !ok {
		return nil, fmt.Errorf("not a share link")
	}
	var (
		ob  *Outbound
		err error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		ob, err = parseVLESSOrTrojan(link, ProtoVLESS)
	case "trojan":
		ob, err = parseVLESSOrTrojan(link, ProtoTrojan)
	case "vmess":
		ob, err = parseVMess(link)
	case "ss":
		ob, err = parseShadowsocks(link)
	case "hysteria2", "hy2":
		ob, err = parseHysteria2(link)
	case "tuic":
		ob, err = parseTUIC(link)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedScheme, scheme)
	}
	if err != nil {
		return nil, err
	}
	if err := ob.Validate(); err != nil {
		return nil, err
	}
	ob.ID = StableID(ob)
	if ob.Remark == "" {
		ob.Remark = net.JoinHostPort(ob.Server, strconv.Itoa(ob.Port))
	}
	return ob, nil
}

// StableID derives an ID from the fields that identify a server, so
// re-importing the same link (or refreshing a subscription) keeps the ID and
// the profiles that point at it. The remark is deliberately excluded.
func StableID(o *Outbound) string {
	h := sha256.New()
	if len(o.RawXray) > 0 || len(o.RawSingBox) > 0 {
		h.Write(o.RawXray)
		h.Write(o.RawSingBox)
	} else {
		fmt.Fprintf(h, "%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
			o.Protocol, strings.ToLower(o.Server), o.Port, o.UUID, o.Password, o.Method, o.Flow,
			o.Transport.Type, o.Transport.Host, o.Transport.Path, o.Transport.ServiceName,
			o.Security.Type, o.Security.SNI, o.Security.PublicKey)
	}
	return "ob-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// --- shared helpers -------------------------------------------------------

func splitHostPort(hostport string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, fmt.Errorf("bad host:port %q: %w", hostport, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return host, port, nil
}

// decodeBase64Loose accepts std / URL alphabets, with or without padding, and
// tolerates embedded whitespace (common in subscription bodies).
func decodeBase64Loose(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func fragmentRemark(u *url.URL) string {
	if u.Fragment != "" {
		return strings.TrimSpace(u.Fragment)
	}
	return ""
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// normaliseNetwork maps the many spellings of a transport to ours.
func normaliseNetwork(n string) string {
	switch strings.ToLower(n) {
	case "", "tcp", "raw":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "grpc", "gun":
		return "grpc"
	case "httpupgrade":
		return "httpupgrade"
	case "xhttp", "splithttp":
		return "xhttp"
	case "h2", "http":
		return "h2"
	case "kcp", "mkcp":
		return "kcp"
	case "quic":
		return "quic"
	}
	return strings.ToLower(n)
}

// applyStreamQuery fills transport + TLS fields from the query parameters
// shared by vless:// and trojan:// links (and the AEAD vmess:// form).
func applyStreamQuery(o *Outbound, q url.Values) {
	t := &o.Transport
	t.Type = normaliseNetwork(q.Get("type"))
	t.Host = q.Get("host")
	t.Path = q.Get("path")
	t.HeaderType = q.Get("headerType")
	t.Seed = q.Get("seed")
	switch t.Type {
	case "grpc":
		t.ServiceName = q.Get("serviceName")
		t.Authority = q.Get("authority")
		t.Mode = q.Get("mode")
		if t.ServiceName == "" && t.Path != "" {
			t.ServiceName = t.Path
			t.Path = ""
		}
	case "xhttp":
		t.Mode = q.Get("mode")
		if extra := q.Get("extra"); extra != "" {
			t.Extra = []byte(extra)
		}
	case "kcp":
		if t.Seed == "" {
			t.Seed = q.Get("path") // some clients put the kcp seed in path
		}
	}
	if t.HeaderType == "none" {
		t.HeaderType = ""
	}

	s := &o.Security
	s.Type = strings.ToLower(q.Get("security"))
	if s.Type == "" {
		s.Type = "none"
	}
	if s.Type == "xtls" { // legacy alias
		s.Type = "tls"
	}
	s.SNI = firstNonEmpty(q.Get("sni"), q.Get("peer"))
	s.ALPN = splitList(q.Get("alpn"))
	s.Fingerprint = q.Get("fp")
	s.AllowInsecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
	s.PublicKey = q.Get("pbk")
	s.ShortID = q.Get("sid")
	s.SpiderX = q.Get("spx")
	s.ECH = q.Get("ech")
	s.PinSHA256 = q.Get("pcs")
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// --- vless:// and trojan:// ----------------------------------------------

func parseVLESSOrTrojan(link, proto string) (*Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", proto, err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", proto, err)
	}
	if u.User == nil {
		return nil, fmt.Errorf("%s: missing credentials", proto)
	}
	cred := u.User.Username()
	if pw, ok := u.User.Password(); ok { // tolerate user:pass forms
		cred = cred + ":" + pw
	}
	q := u.Query()
	o := &Outbound{Protocol: proto, Server: host, Port: port, Remark: fragmentRemark(u)}
	if proto == ProtoVLESS {
		o.UUID = cred
		o.Flow = q.Get("flow")
		o.Encryption = firstNonEmpty(q.Get("encryption"), "none")
	} else {
		o.Password = cred
		if q.Get("security") == "" {
			q.Set("security", "tls") // trojan is TLS unless stated otherwise
		}
	}
	applyStreamQuery(o, q)
	return o, nil
}

// --- vmess:// --------------------------------------------------------------

// vmessJSON is the de-facto v2rayN base64 JSON format. Several fields are
// emitted as either strings or numbers in the wild, hence flexString.
type vmessJSON struct {
	V    flexString `json:"v"`
	PS   string     `json:"ps"`
	Add  string     `json:"add"`
	Port flexString `json:"port"`
	ID   string     `json:"id"`
	Aid  flexString `json:"aid"`
	Scy  string     `json:"scy"`
	Net  string     `json:"net"`
	Type string     `json:"type"`
	Host string     `json:"host"`
	Path string     `json:"path"`
	TLS  string     `json:"tls"`
	SNI  string     `json:"sni"`
	ALPN string     `json:"alpn"`
	FP   string     `json:"fp"`
}

func parseVMess(link string) (*Outbound, error) {
	body := strings.TrimPrefix(strings.TrimPrefix(link, "vmess://"), "VMESS://")
	if strings.Contains(body, "@") {
		// AEAD/"standard" form: vmess://uuid@host:port?type=..&security=..#remark
		u, err := url.Parse(link)
		if err != nil {
			return nil, fmt.Errorf("vmess: %w", err)
		}
		host, port, err := splitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("vmess: %w", err)
		}
		q := u.Query()
		o := &Outbound{Protocol: ProtoVMess, Server: host, Port: port, Remark: fragmentRemark(u)}
		if u.User != nil {
			o.UUID = u.User.Username()
		}
		o.Method = firstNonEmpty(q.Get("encryption"), "auto")
		applyStreamQuery(o, q)
		return o, nil
	}
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	raw, err := decodeBase64Loose(body)
	if err != nil {
		return nil, fmt.Errorf("vmess: bad base64: %w", err)
	}
	var v vmessJSON
	if err := jsonUnmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("vmess: bad json: %w", err)
	}
	port, err := strconv.Atoi(string(v.Port))
	if err != nil {
		return nil, fmt.Errorf("vmess: bad port %q", v.Port)
	}
	aid, _ := strconv.Atoi(string(v.Aid))
	o := &Outbound{
		Protocol: ProtoVMess,
		Remark:   strings.TrimSpace(v.PS),
		Server:   strings.Trim(v.Add, "[]"),
		Port:     port,
		UUID:     v.ID,
		AlterID:  aid,
		Method:   firstNonEmpty(v.Scy, "auto"),
	}
	o.Transport.Type = normaliseNetwork(v.Net)
	o.Transport.Host = v.Host
	o.Transport.Path = v.Path
	switch o.Transport.Type {
	case "grpc":
		o.Transport.ServiceName = v.Path
		o.Transport.Path = ""
		o.Transport.Mode = v.Type
	case "tcp":
		if v.Type != "" && v.Type != "none" {
			o.Transport.HeaderType = v.Type
		}
	case "kcp":
		if v.Type != "" && v.Type != "none" {
			o.Transport.HeaderType = v.Type
		}
		o.Transport.Seed = v.Path
		o.Transport.Path = ""
	case "xhttp":
		o.Transport.Mode = v.Type
	}
	o.Security.Type = "none"
	if strings.EqualFold(v.TLS, "tls") || strings.EqualFold(v.TLS, "reality") {
		o.Security.Type = strings.ToLower(v.TLS)
	}
	o.Security.SNI = v.SNI
	o.Security.ALPN = splitList(v.ALPN)
	o.Security.Fingerprint = v.FP
	return o, nil
}

// --- ss:// -----------------------------------------------------------------

func parseShadowsocks(link string) (*Outbound, error) {
	rest := link[len("ss://"):]
	remark := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		remark, _ = url.PathUnescape(rest[i+1:])
		rest = rest[:i]
	}
	o := &Outbound{Protocol: ProtoShadowsocks, Remark: strings.TrimSpace(remark)}

	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		// SIP002: ss://userinfo@host:port[/][?plugin=...]
		userinfo := rest[:at]
		hostPart := rest[at+1:]
		query := ""
		if i := strings.IndexByte(hostPart, '?'); i >= 0 {
			query = hostPart[i+1:]
			hostPart = hostPart[:i]
		}
		hostPart = strings.TrimSuffix(hostPart, "/")
		host, port, err := splitHostPort(hostPart)
		if err != nil {
			return nil, fmt.Errorf("ss: %w", err)
		}
		o.Server, o.Port = host, port
		method, password, err := ssUserinfo(userinfo)
		if err != nil {
			return nil, err
		}
		o.Method, o.Password = method, password
		if query != "" {
			q, err := url.ParseQuery(query)
			if err == nil {
				if p := q.Get("plugin"); p != "" {
					name, opts, _ := strings.Cut(p, ";")
					o.Plugin, o.PluginOpts = name, opts
				}
			}
		}
		return o, nil
	}

	// Legacy: ss://base64(method:password@host:port)
	raw, err := decodeBase64Loose(rest)
	if err != nil {
		return nil, fmt.Errorf("ss: bad legacy base64: %w", err)
	}
	s := string(raw)
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return nil, fmt.Errorf("ss: bad legacy link")
	}
	method, password, ok := strings.Cut(s[:at], ":")
	if !ok {
		return nil, fmt.Errorf("ss: bad legacy credentials")
	}
	host, port, err := splitHostPort(s[at+1:])
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	o.Method, o.Password, o.Server, o.Port = method, password, host, port
	return o, nil
}

// ssUserinfo decodes SIP002 userinfo: base64url(method:password) for stream
// ciphers, or percent-encoded method:password (required for 2022 ciphers).
func ssUserinfo(userinfo string) (string, string, error) {
	if dec, err := url.PathUnescape(userinfo); err == nil && strings.Contains(dec, ":") {
		m, p, _ := strings.Cut(dec, ":")
		if isSSMethod(m) {
			return m, p, nil
		}
	}
	raw, err := decodeBase64Loose(userinfo)
	if err != nil {
		return "", "", fmt.Errorf("ss: bad userinfo")
	}
	m, p, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", fmt.Errorf("ss: bad userinfo")
	}
	return m, p, nil
}

func isSSMethod(m string) bool {
	m = strings.ToLower(m)
	return strings.HasPrefix(m, "aes-") || strings.HasPrefix(m, "chacha20") ||
		strings.HasPrefix(m, "xchacha20") || strings.HasPrefix(m, "2022-") ||
		m == "none" || m == "plain" || strings.HasPrefix(m, "rc4")
}

// --- hysteria2:// / hy2:// ------------------------------------------------

func parseHysteria2(link string) (*Outbound, error) {
	// net/url rejects port-hopping specs (host:20000-30000), so pull the
	// port spec out of the authority before handing the rest to url.Parse.
	scheme, rest, _ := strings.Cut(link, "://")
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, tail := rest[:end], rest[end:]
	userinfo, hostport := "", authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo, hostport = authority[:at+1], authority[at+1:]
	}
	host, portSpec := hostport, "443"
	if strings.HasPrefix(hostport, "[") {
		if i := strings.Index(hostport, "]"); i >= 0 {
			host = hostport[:i+1]
			if strings.HasPrefix(hostport[i+1:], ":") {
				portSpec = hostport[i+2:]
			}
		}
	} else if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		host, portSpec = hostport[:i], hostport[i+1:]
	}
	u, err := url.Parse(scheme + "://" + userinfo + host + tail)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	q := u.Query()
	o := &Outbound{Protocol: ProtoHysteria2, Remark: fragmentRemark(u), Hysteria2: &Hysteria2Options{}}
	o.Server = strings.Trim(host, "[]")
	if p, err := strconv.Atoi(portSpec); err == nil {
		o.Port = p
	} else {
		first := strings.FieldsFunc(portSpec, func(r rune) bool { return r == ',' || r == '-' })
		if len(first) == 0 {
			return nil, fmt.Errorf("hysteria2: bad port %q", portSpec)
		}
		if o.Port, err = strconv.Atoi(first[0]); err != nil {
			return nil, fmt.Errorf("hysteria2: bad port %q", portSpec)
		}
		o.Hysteria2.Ports = portSpec
	}
	if mp := q.Get("mport"); mp != "" {
		o.Hysteria2.Ports = mp
	}
	if u.User != nil {
		o.Password = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			o.Password += ":" + pw
		}
	}
	o.Hysteria2.Obfs = q.Get("obfs")
	o.Hysteria2.ObfsPassword = q.Get("obfs-password")
	o.Security = Security{
		Type:          "tls",
		SNI:           q.Get("sni"),
		AllowInsecure: truthy(q.Get("insecure")),
		ALPN:          splitList(q.Get("alpn")),
		PinSHA256:     q.Get("pinSHA256"),
	}
	o.Transport.Type = "quic"
	return o, nil
}

// --- tuic:// -----------------------------------------------------------------

func parseTUIC(link string) (*Outbound, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	q := u.Query()
	o := &Outbound{Protocol: ProtoTUIC, Server: host, Port: port, Remark: fragmentRemark(u), TUIC: &TUICOptions{}}
	if u.User != nil {
		o.UUID = u.User.Username()
		o.Password, _ = u.User.Password()
	}
	o.TUIC.CongestionControl = firstNonEmpty(q.Get("congestion_control"), q.Get("congestion-control"))
	o.TUIC.UDPRelayMode = firstNonEmpty(q.Get("udp_relay_mode"), q.Get("udp-relay-mode"))
	o.TUIC.ZeroRTT = truthy(q.Get("zero_rtt_handshake")) || truthy(q.Get("reduce_rtt"))
	o.Security = Security{
		Type:          "tls",
		SNI:           q.Get("sni"),
		AllowInsecure: truthy(q.Get("allow_insecure")) || truthy(q.Get("insecure")),
		ALPN:          splitList(q.Get("alpn")),
	}
	o.Transport.Type = "quic"
	return o, nil
}
