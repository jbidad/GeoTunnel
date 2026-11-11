package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ToLink renders an outbound back into a share link. With redact=true the
// credentials are replaced by a placeholder, which is what exports and logs
// must use.
func ToLink(o *Outbound, redact bool) (string, error) {
	if len(o.RawXray) > 0 || len(o.RawSingBox) > 0 {
		return "", fmt.Errorf("raw JSON outbounds have no share link form")
	}
	secret := func(s string) string {
		if redact && s != "" {
			return RedactedPlaceholder
		}
		return s
	}
	hostport := net.JoinHostPort(o.Server, strconv.Itoa(o.Port))
	frag := ""
	if o.Remark != "" {
		frag = "#" + url.PathEscape(o.Remark)
	}
	switch o.Protocol {
	case ProtoVLESS, ProtoTrojan:
		q := streamQuery(o)
		cred := o.UUID
		if o.Protocol == ProtoVLESS {
			q.Set("encryption", firstNonEmpty(o.Encryption, "none"))
			if o.Flow != "" {
				q.Set("flow", o.Flow)
			}
		} else {
			cred = o.Password
		}
		u := url.URL{Scheme: o.Protocol, User: url.User(secret(cred)), Host: hostport, RawQuery: q.Encode()}
		return u.String() + frag, nil
	case ProtoVMess:
		v := M{
			"v": "2", "ps": o.Remark, "add": o.Server, "port": strconv.Itoa(o.Port), "id": secret(o.UUID),
			"aid": strconv.Itoa(o.AlterID), "scy": firstNonEmpty(o.Method, "auto"), "net": o.Transport.Type,
			"type": "none", "host": o.Transport.Host, "path": o.Transport.Path, "tls": "",
			"sni": o.Security.SNI, "alpn": strings.Join(o.Security.ALPN, ","), "fp": o.Security.Fingerprint,
		}
		switch o.Transport.Type {
		case "grpc":
			v["path"] = o.Transport.ServiceName
			v["type"] = firstNonEmpty(o.Transport.Mode, "gun")
		case "tcp", "kcp":
			v["type"] = firstNonEmpty(o.Transport.HeaderType, "none")
			if o.Transport.Type == "kcp" {
				v["path"] = o.Transport.Seed
			}
		case "xhttp":
			v["type"] = o.Transport.Mode
		}
		if o.Security.Type != "none" && o.Security.Type != "" {
			v["tls"] = o.Security.Type
		}
		b, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
	case ProtoShadowsocks:
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(o.Method + ":" + secret(o.Password)))
		if strings.HasPrefix(o.Method, "2022-") {
			userinfo = url.PathEscape(o.Method) + ":" + url.PathEscape(secret(o.Password))
		}
		s := "ss://" + userinfo + "@" + hostport
		if o.Plugin != "" {
			p := o.Plugin
			if o.PluginOpts != "" {
				p += ";" + o.PluginOpts
			}
			s += "/?" + url.Values{"plugin": {p}}.Encode()
		}
		return s + frag, nil
	case ProtoHysteria2:
		q := url.Values{}
		if o.Security.SNI != "" {
			q.Set("sni", o.Security.SNI)
		}
		if o.Security.AllowInsecure {
			q.Set("insecure", "1")
		}
		if len(o.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(o.Security.ALPN, ","))
		}
		if o.Security.PinSHA256 != "" {
			q.Set("pinSHA256", o.Security.PinSHA256)
		}
		if h := o.Hysteria2; h != nil {
			if h.Obfs != "" {
				q.Set("obfs", h.Obfs)
				q.Set("obfs-password", secret(h.ObfsPassword))
			}
			if h.Ports != "" {
				q.Set("mport", h.Ports)
			}
		}
		u := url.URL{Scheme: "hysteria2", User: url.User(secret(o.Password)), Host: hostport, Path: "/", RawQuery: q.Encode()}
		return u.String() + frag, nil
	case ProtoTUIC:
		q := url.Values{}
		if o.Security.SNI != "" {
			q.Set("sni", o.Security.SNI)
		}
		if o.Security.AllowInsecure {
			q.Set("allow_insecure", "1")
		}
		if len(o.Security.ALPN) > 0 {
			q.Set("alpn", strings.Join(o.Security.ALPN, ","))
		}
		if t := o.TUIC; t != nil {
			if t.CongestionControl != "" {
				q.Set("congestion_control", t.CongestionControl)
			}
			if t.UDPRelayMode != "" {
				q.Set("udp_relay_mode", t.UDPRelayMode)
			}
			if t.ZeroRTT {
				q.Set("zero_rtt_handshake", "1")
			}
		}
		u := url.URL{Scheme: "tuic", User: url.UserPassword(secret(o.UUID), secret(o.Password)), Host: hostport, RawQuery: q.Encode()}
		return u.String() + frag, nil
	}
	return "", fmt.Errorf("unsupported protocol %q", o.Protocol)
}

func streamQuery(o *Outbound) url.Values {
	q := url.Values{}
	t, s := o.Transport, o.Security
	q.Set("type", firstNonEmpty(t.Type, "tcp"))
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("host", t.Host)
	set("path", t.Path)
	set("headerType", t.HeaderType)
	set("serviceName", t.ServiceName)
	set("authority", t.Authority)
	set("mode", t.Mode)
	set("seed", t.Seed)
	if len(t.Extra) > 0 {
		q.Set("extra", string(t.Extra))
	}
	q.Set("security", firstNonEmpty(s.Type, "none"))
	set("sni", s.SNI)
	set("alpn", strings.Join(s.ALPN, ","))
	set("fp", s.Fingerprint)
	set("pbk", s.PublicKey)
	set("sid", s.ShortID)
	set("spx", s.SpiderX)
	set("ech", s.ECH)
	set("pcs", s.PinSHA256)
	if s.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	return q
}
