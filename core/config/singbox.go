package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// SingBoxOutbound renders an outbound as a native sing-box outbound object.
func SingBoxOutbound(o *Outbound, tag string) (M, error) {
	if len(o.RawSingBox) > 0 {
		var m M
		if err := json.Unmarshal(o.RawSingBox, &m); err != nil {
			return nil, fmt.Errorf("raw sing-box outbound: %w", err)
		}
		m["tag"] = tag
		return m, nil
	}
	out := M{"tag": tag, "server": o.Server, "server_port": o.Port}
	switch o.Protocol {
	case ProtoVLESS:
		out["type"] = "vless"
		out["uuid"] = o.UUID
		if o.Flow != "" {
			out["flow"] = o.Flow
		}
		if o.Encryption != "" && o.Encryption != "none" {
			return nil, fmt.Errorf("sing-box: VLESS encryption %q is Xray-only", o.Encryption)
		}
	case ProtoVMess:
		out["type"] = "vmess"
		out["uuid"] = o.UUID
		out["security"] = firstNonEmpty(o.Method, "auto")
		if o.AlterID > 0 {
			out["alter_id"] = o.AlterID
		}
	case ProtoTrojan:
		out["type"] = "trojan"
		out["password"] = o.Password
	case ProtoShadowsocks:
		out["type"] = "shadowsocks"
		out["method"] = o.Method
		out["password"] = o.Password
		if o.Plugin != "" {
			plugin := o.Plugin
			if plugin == "simple-obfs" {
				plugin = "obfs-local"
			}
			out["plugin"] = plugin
			out["plugin_opts"] = o.PluginOpts
		}
	case ProtoHysteria2:
		out["type"] = "hysteria2"
		out["password"] = o.Password
		if h := o.Hysteria2; h != nil {
			if h.Obfs != "" {
				out["obfs"] = M{"type": h.Obfs, "password": h.ObfsPassword}
			}
			if h.Ports != "" {
				out["server_ports"] = hysteriaPortRanges(h.Ports)
				delete(out, "server_port")
			}
			if h.UpMbps > 0 {
				out["up_mbps"] = h.UpMbps
			}
			if h.DownMbps > 0 {
				out["down_mbps"] = h.DownMbps
			}
		}
	case ProtoTUIC:
		out["type"] = "tuic"
		out["uuid"] = o.UUID
		if o.Password != "" {
			out["password"] = o.Password
		}
		if t := o.TUIC; t != nil {
			if t.CongestionControl != "" {
				out["congestion_control"] = t.CongestionControl
			}
			if t.UDPRelayMode != "" {
				out["udp_relay_mode"] = t.UDPRelayMode
			}
			if t.ZeroRTT {
				out["zero_rtt_handshake"] = true
			}
		}
	default:
		return nil, fmt.Errorf("sing-box: unsupported protocol %q", o.Protocol)
	}

	if tls := singBoxTLS(o); tls != nil {
		out["tls"] = tls
	}
	if o.Protocol != ProtoHysteria2 && o.Protocol != ProtoTUIC && o.Protocol != ProtoShadowsocks {
		tr, err := singBoxTransport(o)
		if err != nil {
			return nil, err
		}
		if tr != nil {
			out["transport"] = tr
		}
	}
	return out, nil
}

func hysteriaPortRanges(spec string) []string {
	var out []string
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			out = append(out, strings.Replace(part, "-", ":", 1))
		} else {
			out = append(out, part+":"+part)
		}
	}
	return out
}

func singBoxTLS(o *Outbound) M {
	s := o.Security
	quic := o.Protocol == ProtoHysteria2 || o.Protocol == ProtoTUIC
	if !quic && (s.Type == "" || s.Type == "none") {
		return nil
	}
	tls := M{"enabled": true}
	if sni := firstNonEmpty(s.SNI, hostOnly(o.Transport.Host)); sni != "" {
		tls["server_name"] = sni
	}
	if s.AllowInsecure {
		tls["insecure"] = true
	}
	if len(s.ALPN) > 0 {
		tls["alpn"] = s.ALPN
	}
	if !quic {
		fp := strings.ToLower(s.Fingerprint)
		if s.Type == "reality" && fp == "" {
			fp = "chrome"
		}
		if fp != "" && fp != "none" {
			tls["utls"] = M{"enabled": true, "fingerprint": fp}
		}
	}
	if s.Type == "reality" {
		tls["reality"] = compact(M{"enabled": true, "public_key": s.PublicKey, "short_id": s.ShortID})
	}
	return tls
}

func singBoxTransport(o *Outbound) (M, error) {
	t := o.Transport
	switch t.Type {
	case "", "tcp":
		if t.HeaderType == "http" {
			return nil, fmt.Errorf("sing-box: tcp http-header obfuscation is Xray-only")
		}
		return nil, nil
	case "ws":
		ws := M{"type": "ws", "path": firstNonEmpty(t.Path, "/")}
		// v2ray-style early data: path?ed=2048
		if u, err := url.Parse(t.Path); err == nil {
			if ed := u.Query().Get("ed"); ed != "" {
				if n, err := strconv.Atoi(ed); err == nil {
					q := u.Query()
					q.Del("ed")
					u.RawQuery = q.Encode()
					ws["path"] = firstNonEmpty(u.String(), "/")
					ws["max_early_data"] = n
					ws["early_data_header_name"] = "Sec-WebSocket-Protocol"
				}
			}
		}
		if t.Host != "" {
			ws["headers"] = M{"Host": hostOnly(t.Host)}
		}
		return ws, nil
	case "grpc":
		return M{"type": "grpc", "service_name": t.ServiceName}, nil
	case "httpupgrade":
		return compact(M{"type": "httpupgrade", "host": hostOnly(t.Host), "path": firstNonEmpty(t.Path, "/")}), nil
	case "h2", "http":
		h := M{"type": "http", "path": firstNonEmpty(t.Path, "/")}
		if t.Host != "" {
			h["host"] = splitList(t.Host)
		}
		return h, nil
	case "quic":
		return M{"type": "quic"}, nil
	}
	return nil, fmt.Errorf("sing-box: transport %q is not supported by sing-box", t.Type)
}

// SingBoxBuild is the result of BuildSingBox.
type SingBoxBuild struct {
	Config []byte
	// ProfileOutbound maps profile id -> sing-box outbound tag; "" means the
	// profile is blocked (no usable outbound: fail closed).
	ProfileOutbound map[string]string
	Warnings        []string
}

// BuildSingBox renders the routing core: per-profile mixed inbounds, the TUN
// inbound with per-app rules, per-profile remote DNS and the kill switch.
// xray maps outbound id -> the internal Xray SOCKS inbound that runs it.
func BuildSingBox(s *State, xray map[string]XrayInbound) (*SingBoxBuild, error) {
	res := &SingBoxBuild{ProfileOutbound: map[string]string{}}
	platform := s.Settings.Platform

	var (
		outbounds []any
		inbounds  []any
		rules     []any
		dnsRules  []any
		dnsSrv    = []any{M{"type": "local", "tag": "local"}}
		emitted   = map[string]bool{}
	)
	emit := func(o *Outbound) (string, error) {
		tag := o.ID
		if emitted[tag] {
			return tag, nil
		}
		eng, err := o.Engine()
		if err != nil {
			return "", err
		}
		var ob M
		if eng == EngineXray {
			in, ok := xray[o.ID]
			if !ok {
				return "", fmt.Errorf("no xray inbound allocated for %s", o.ID)
			}
			ob = M{"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": in.Port,
				"version": "5", "username": in.User, "password": in.Pass}
		} else {
			ob, err = SingBoxOutbound(o, tag)
			if err != nil {
				return "", err
			}
		}
		emitted[tag] = true
		outbounds = append(outbounds, ob)
		return tag, nil
	}

	remoteDNS, err := singBoxRemoteDNS(s.Settings.RemoteDNS)
	if err != nil {
		return nil, err
	}

	// Resolve each profile to an outbound tag.
	active := make([]*Profile, 0, len(s.Profiles))
	for _, p := range s.Profiles {
		if p.Disabled {
			continue
		}
		active = append(active, p)
		members, group := s.ResolveOutbounds(p)
		var tags []string
		for _, o := range members {
			tag, err := emit(o)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("profile %s: skipping outbound %s: %v", p.ID, o.ID, err))
				continue
			}
			tags = append(tags, tag)
		}
		switch {
		case len(tags) == 0:
			res.ProfileOutbound[p.ID] = ""
			res.Warnings = append(res.Warnings, fmt.Sprintf("profile %s has no usable outbound; its traffic is blocked", p.ID))
		case group:
			tag := "p-" + p.ID
			outbounds = append(outbounds, M{"type": "urltest", "tag": tag, "outbounds": tags,
				"url": s.Settings.TestURL, "interval": "3m", "tolerance": 50})
			res.ProfileOutbound[p.ID] = tag
		default:
			res.ProfileOutbound[p.ID] = tags[0]
		}
		if out := res.ProfileOutbound[p.ID]; out != "" {
			srv := M{}
			for k, v := range remoteDNS {
				srv[k] = v
			}
			srv["tag"] = "dns-" + p.ID
			srv["detour"] = out
			dnsSrv = append(dnsSrv, srv)
		}
	}
	outbounds = append(outbounds, M{"type": "direct", "tag": "direct"})

	// Per-profile local inbounds (web container, launch-with-profile).
	for _, p := range active {
		tag := "mixed-" + p.ID
		inbounds = append(inbounds, M{"type": "mixed", "tag": tag, "listen": "127.0.0.1", "listen_port": p.LocalPort})
		rules = append(rules, routeTo(M{"inbound": []string{tag}}, res.ProfileOutbound[p.ID]))
	}

	// TUN for native apps.
	tunNeeded := false
	var includePkgs []string
	deviceProfile := ""
	for _, p := range active {
		for _, t := range p.Targets {
			switch t.Type {
			case TargetAndroidPackage:
				includePkgs = append(includePkgs, t.Value)
				tunNeeded = true
			case TargetProcess, TargetProcessPath:
				tunNeeded = true
			case TargetDevice:
				if deviceProfile != "" && deviceProfile != p.ID {
					return nil, fmt.Errorf("only one profile can own the whole device (%s and %s)", deviceProfile, p.ID)
				}
				deviceProfile = p.ID
				tunNeeded = true
			}
		}
	}
	tunNeeded = tunNeeded && s.Settings.TUN.Enabled
	if tunNeeded {
		tun := M{
			"type": "tun", "tag": "tun-in",
			"address":     []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":         firstPositive(s.Settings.TUN.MTU, 9000),
			"auto_route":  true,
			"strict_route": true,
			"stack":       firstNonEmpty(s.Settings.TUN.Stack, "mixed"),
		}
		if platform == "android" && deviceProfile == "" {
			// Only the targeted apps enter the VPN at all
			// (VpnService.Builder.addAllowedApplication); everything else
			// never touches the tunnel.
			sort.Strings(includePkgs)
			tun["include_package"] = dedupe(includePkgs)
		}
		inbounds = append(inbounds, tun)
		rules = append(rules, M{"inbound": []string{"tun-in"}, "action": "sniff"})

		for _, p := range active {
			out := res.ProfileOutbound[p.ID]
			for _, sel := range targetSelectors(p.Targets) {
				if out == "" {
					rules = append(rules, withAction(sel, M{"action": "reject"}))
					continue
				}
				rules = append(rules, withAction(sel, M{"protocol": "dns", "action": "hijack-dns"}))
				dnsRules = append(dnsRules, withAction(sel, M{"action": "route", "server": "dns-" + p.ID}))
				rules = append(rules, routeTo(sel, out))
			}
		}
		if deviceProfile != "" {
			out := res.ProfileOutbound[deviceProfile]
			sel := M{"inbound": []string{"tun-in"}}
			if out == "" {
				rules = append(rules, withAction(sel, M{"action": "reject"}))
			} else {
				rules = append(rules, withAction(sel, M{"protocol": "dns", "action": "hijack-dns"}))
				rules = append(rules, withAction(M{"ip_is_private": true}, M{"action": "route", "outbound": "direct"}))
				rules = append(rules, routeTo(sel, out))
				dnsRules = append(dnsRules, M{"inbound": []string{"tun-in"}, "action": "route", "server": "dns-" + deviceProfile})
			}
		}
	}

	route := M{
		"rules":                   rules,
		"final":                   "direct",
		"default_domain_resolver": M{"server": "local"},
	}
	if tunNeeded {
		route["auto_detect_interface"] = true
	}
	cfg := M{
		"log":       M{"level": singBoxLogLevel(s.Settings.LogLevel), "timestamp": true},
		"dns":       M{"servers": dnsSrv, "rules": dnsRules, "final": "local"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
	}
	if len(dnsRules) == 0 {
		delete(cfg["dns"].(M), "rules")
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	res.Config = b
	return res, nil
}

func routeTo(sel M, out string) M {
	if out == "" {
		return withAction(sel, M{"action": "reject"})
	}
	return withAction(sel, M{"action": "route", "outbound": out})
}

func withAction(sel M, extra M) M {
	m := M{}
	for k, v := range sel {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// targetSelectors returns one rule selector per target kind. sing-box ANDs
// different match fields, so process_name and package_name must not share a
// rule.
func targetSelectors(ts []Target) []M {
	byKind := map[string][]string{}
	for _, t := range ts {
		switch t.Type {
		case TargetProcess:
			byKind["process_name"] = append(byKind["process_name"], t.Value)
		case TargetProcessPath:
			byKind["process_path"] = append(byKind["process_path"], t.Value)
		case TargetAndroidPackage:
			byKind["package_name"] = append(byKind["package_name"], t.Value)
		}
	}
	var out []M
	for _, k := range []string{"package_name", "process_name", "process_path"} {
		if v := byKind[k]; len(v) > 0 {
			sort.Strings(v)
			out = append(out, M{k: dedupe(v)})
		}
	}
	return out
}

// singBoxRemoteDNS turns a resolver URL into a sing-box DNS server object.
// Supported: https://ip/path, tls://ip, tcp://ip, plain ip (tcp, since UDP
// cannot pass every outbound).
func singBoxRemoteDNS(raw string) (M, error) {
	if !strings.Contains(raw, "://") {
		return M{"type": "tcp", "server": raw}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("remoteDns: %w", err)
	}
	host := u.Hostname()
	srv := M{"server": host}
	if p := u.Port(); p != "" {
		n, _ := strconv.Atoi(p)
		srv["server_port"] = n
	}
	switch u.Scheme {
	case "https":
		srv["type"] = "https"
		if u.Path != "" && u.Path != "/dns-query" {
			srv["path"] = u.Path
		}
	case "tls":
		srv["type"] = "tls"
	case "tcp":
		srv["type"] = "tcp"
	default:
		return nil, fmt.Errorf("remoteDns scheme %q not supported (https, tls, tcp)", u.Scheme)
	}
	return srv, nil
}

func singBoxLogLevel(l string) string {
	switch l {
	case "trace", "debug", "info", "warn", "error":
		return l
	case "warning":
		return "warn"
	}
	return "info"
}

func firstPositive(v ...int) int {
	for _, n := range v {
		if n > 0 {
			return n
		}
	}
	return 0
}

func dedupe(in []string) []string {
	out := in[:0]
	var prev string
	for i, s := range in {
		if i > 0 && s == prev {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}
