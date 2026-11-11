package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// XrayOutbound renders an outbound as an Xray-core outbound object.
func XrayOutbound(o *Outbound, tag string) (M, error) {
	if len(o.RawXray) > 0 {
		var m M
		if err := json.Unmarshal(o.RawXray, &m); err != nil {
			return nil, fmt.Errorf("raw xray outbound: %w", err)
		}
		m["tag"] = tag
		return m, nil
	}
	var settings M
	switch o.Protocol {
	case ProtoVLESS:
		settings = compact(M{"address": o.Server, "port": o.Port, "id": o.UUID,
			"encryption": firstNonEmpty(o.Encryption, "none"), "flow": o.Flow})
	case ProtoVMess:
		settings = M{"address": o.Server, "port": o.Port, "id": o.UUID, "security": firstNonEmpty(o.Method, "auto")}
	case ProtoTrojan:
		settings = M{"address": o.Server, "port": o.Port, "password": o.Password}
	case ProtoShadowsocks:
		if o.Plugin != "" {
			return nil, fmt.Errorf("xray: shadowsocks plugins are not supported")
		}
		settings = M{"address": o.Server, "port": o.Port, "method": o.Method, "password": o.Password}
	default:
		return nil, fmt.Errorf("xray: protocol %q not handled by Xray builder", o.Protocol)
	}
	stream, err := xrayStream(o)
	if err != nil {
		return nil, err
	}
	return M{"tag": tag, "protocol": o.Protocol, "settings": settings, "streamSettings": stream}, nil
}

func xrayStream(o *Outbound) (M, error) {
	t, s := o.Transport, o.Security
	network := t.Type
	if network == "" {
		network = "tcp"
	}
	stream := M{"network": network}
	switch network {
	case "tcp":
		if t.HeaderType == "http" {
			req := M{"path": []string{firstNonEmpty(t.Path, "/")}}
			if t.Host != "" {
				req["headers"] = M{"Host": splitList(t.Host)}
			}
			stream["tcpSettings"] = M{"header": M{"type": "http", "request": req}}
		}
	case "ws":
		stream["wsSettings"] = compact(M{"path": firstNonEmpty(t.Path, "/"), "host": t.Host})
	case "grpc":
		stream["grpcSettings"] = compact(M{"serviceName": t.ServiceName, "authority": t.Authority, "multiMode": t.Mode == "multi"})
	case "httpupgrade":
		stream["httpupgradeSettings"] = compact(M{"path": firstNonEmpty(t.Path, "/"), "host": t.Host})
	case "xhttp":
		x := compact(M{"path": firstNonEmpty(t.Path, "/"), "host": t.Host, "mode": firstNonEmpty(t.Mode, "auto")})
		if len(t.Extra) > 0 {
			var extra any
			if err := json.Unmarshal(t.Extra, &extra); err != nil {
				return nil, fmt.Errorf("xhttp extra is not valid JSON: %w", err)
			}
			x["extra"] = extra
		}
		stream["xhttpSettings"] = x
	case "kcp":
		k := M{}
		if t.HeaderType != "" {
			k["header"] = M{"type": t.HeaderType}
		}
		if t.Seed != "" {
			k["seed"] = t.Seed
		}
		stream["kcpSettings"] = k
	default:
		return nil, fmt.Errorf("xray: transport %q is not supported by Xray-core", network)
	}

	switch s.Type {
	case "", "none":
		stream["security"] = "none"
	case "tls":
		if s.AllowInsecure && s.PinSHA256 == "" {
			return nil, fmt.Errorf("xray: allowInsecure is rejected by current Xray-core; a pinned certificate hash (pcs) is required")
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = compact(M{
			"serverName":           firstNonEmpty(s.SNI, hostOnly(t.Host), o.Server),
			"alpn":                 s.ALPN,
			"fingerprint":          strings.ToLower(s.Fingerprint),
			"pinnedPeerCertSha256": s.PinSHA256,
			"echConfigList":        s.ECH,
		})
	case "reality":
		if s.PublicKey == "" {
			return nil, fmt.Errorf("xray: reality needs pbk (public key)")
		}
		stream["security"] = "reality"
		stream["realitySettings"] = compact(M{
			"serverName":  firstNonEmpty(s.SNI, o.Server),
			"fingerprint": firstNonEmpty(strings.ToLower(s.Fingerprint), "chrome"),
			"publicKey":   s.PublicKey,
			"shortId":     s.ShortID,
			"spiderX":     s.SpiderX,
		})
	default:
		return nil, fmt.Errorf("xray: unknown security %q", s.Type)
	}
	return stream, nil
}

func hostOnly(h string) string {
	if i := strings.IndexByte(h, ','); i >= 0 {
		h = h[:i]
	}
	return strings.TrimSpace(h)
}

// XrayInbound is an internal SOCKS inbound that feeds exactly one outbound.
type XrayInbound struct {
	OutboundID string
	Port       int
	User, Pass string
}

// BuildXray renders a complete Xray config: one authenticated loopback SOCKS
// inbound per outbound, each routed to its outbound. The first outbound is a
// blackhole, so anything unmatched is dropped rather than sent somewhere.
func BuildXray(obs []*Outbound, inbounds []XrayInbound, logLevel string) ([]byte, error) {
	byID := map[string]*Outbound{}
	for _, o := range obs {
		byID[o.ID] = o
	}
	cfg := M{
		"log": M{"loglevel": xrayLogLevel(logLevel), "access": "none", "dnsLog": false},
	}
	var ins, outs, rules []any
	outs = append(outs, M{"tag": "block", "protocol": "blackhole"})
	for _, in := range inbounds {
		o := byID[in.OutboundID]
		if o == nil {
			return nil, fmt.Errorf("xray inbound for unknown outbound %s", in.OutboundID)
		}
		out, err := XrayOutbound(o, o.ID)
		if err != nil {
			return nil, fmt.Errorf("outbound %s (%s): %w", o.ID, o.Remark, err)
		}
		outs = append(outs, out)
		inTag := "in-" + o.ID
		ins = append(ins, M{
			"tag": inTag, "listen": "127.0.0.1", "port": in.Port, "protocol": "socks",
			"settings": M{"auth": "password", "accounts": []any{M{"user": in.User, "pass": in.Pass}}, "udp": true, "ip": "127.0.0.1"},
		})
		rules = append(rules, M{"type": "field", "inboundTag": []string{inTag}, "outboundTag": o.ID})
	}
	cfg["inbounds"] = ins
	cfg["outbounds"] = outs
	cfg["routing"] = M{"domainStrategy": "AsIs", "rules": rules}
	return json.MarshalIndent(cfg, "", "  ")
}

func xrayLogLevel(l string) string {
	switch l {
	case "trace", "debug":
		return "debug"
	case "info":
		return "info"
	case "error":
		return "error"
	}
	return "warning"
}
