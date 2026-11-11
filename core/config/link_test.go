package config

import (
	"encoding/base64"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureLinks(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/links.txt")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func TestParseFixtures(t *testing.T) {
	links := fixtureLinks(t)
	if len(links) < 17 {
		t.Fatalf("expected the full fixture set, got %d links", len(links))
	}
	byRemark := map[string]*Outbound{}
	for _, l := range links {
		o, err := ParseLink(l)
		if err != nil {
			t.Fatalf("ParseLink(%.40s...): %v", l, err)
		}
		if !strings.HasPrefix(o.ID, "ob-") || len(o.ID) != 15 {
			t.Errorf("%s: bad id %q", o.Remark, o.ID)
		}
		byRemark[o.Remark] = o
	}

	check := func(remark string, f func(o *Outbound) []any) {
		t.Helper()
		o := byRemark[remark]
		if o == nil {
			t.Errorf("missing %q", remark)
			return
		}
		pairs := f(o)
		for i := 0; i < len(pairs); i += 2 {
			if !reflect.DeepEqual(pairs[i], pairs[i+1]) {
				t.Errorf("%s: field #%d got %#v want %#v", remark, i/2, pairs[i], pairs[i+1])
			}
		}
	}

	check("TR-Istanbul Reality", func(o *Outbound) []any {
		return []any{o.Protocol, ProtoVLESS, o.Server, "203.0.113.10", o.Port, 443,
			o.Flow, "xtls-rprx-vision", o.Encryption, "none", o.Transport.Type, "tcp", o.Transport.HeaderType, "",
			o.Security.Type, "reality", o.Security.SNI, "www.example.com", o.Security.Fingerprint, "chrome",
			o.Security.PublicKey, "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", o.Security.ShortID, "6ba85179e30d4fc2",
			o.Security.SpiderX, "/"}
	})
	check("DE-WS-TLS", func(o *Outbound) []any {
		return []any{o.Transport.Type, "ws", o.Transport.Path, "/ws?ed=2048", o.Transport.Host, "cdn.example.net",
			o.Security.Type, "tls", o.Security.ALPN, []string{"http/1.1"}}
	})
	check("FR-XHTTP", func(o *Outbound) []any {
		return []any{o.Transport.Type, "xhttp", o.Transport.Mode, "auto", o.Transport.Path, "/xh"}
	})
	check("NL-gRPC-Reality", func(o *Outbound) []any {
		return []any{o.Transport.Type, "grpc", o.Transport.ServiceName, "grpcsvc", o.Transport.Mode, "gun",
			o.Security.Type, "reality", o.Security.Fingerprint, "safari", o.Security.ShortID, "ab12"}
	})
	check("V6-HTTPUpgrade", func(o *Outbound) []any {
		return []any{o.Server, "2001:db8::2", o.Port, 8443, o.Transport.Type, "httpupgrade", o.Transport.Path, "/up"}
	})
	check("US-VMess-WS", func(o *Outbound) []any {
		return []any{o.Protocol, ProtoVMess, o.Server, "vm.example.com", o.Port, 443,
			o.UUID, "0b9e9c1e-4d1a-4f4e-9a6e-2f6d8c3b7a51", o.Transport.Type, "ws", o.Transport.Path, "/vmws",
			o.Security.Type, "tls", o.Security.ALPN, []string{"h2", "http/1.1"}, o.Security.Fingerprint, "firefox"}
	})
	check("NL-VMess-gRPC", func(o *Outbound) []any { // numeric port / aid in JSON
		return []any{o.Port, 8443, o.Transport.Type, "grpc", o.Transport.ServiceName, "vmgrpc", o.Transport.Mode, "multi",
			o.Security.SNI, "grpc.example.org"}
	})
	check("VMess-AEAD-HTTPHeader", func(o *Outbound) []any {
		return []any{o.Protocol, ProtoVMess, o.Transport.HeaderType, "http", o.Transport.Host, "bing.example.com", o.Security.Type, "none"}
	})
	check("UK-Trojan", func(o *Outbound) []any {
		return []any{o.Protocol, ProtoTrojan, o.Password, "p@ssw0rd-trojan", o.Security.Type, "tls", o.Security.SNI, "t.example.com"}
	})
	check("Trojan-gRPC", func(o *Outbound) []any {
		return []any{o.Transport.Type, "grpc", o.Transport.ServiceName, "trgrpc"}
	})
	check("SS-AEAD", func(o *Outbound) []any {
		return []any{o.Method, "aes-256-gcm", o.Password, "password", o.Port, 8388}
	})
	check("SS-2022", func(o *Outbound) []any {
		return []any{o.Method, "2022-blake3-aes-128-gcm", o.Password, "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI="}
	})
	check("SS-Legacy", func(o *Outbound) []any {
		return []any{o.Method, "chacha20-ietf-poly1305", o.Password, "legacy-secret", o.Server, "192.0.2.7", o.Port, 8389}
	})
	check("SS-Plugin", func(o *Outbound) []any {
		return []any{o.Plugin, "obfs-local", o.PluginOpts, "obfs=http;obfs-host=example.com"}
	})
	check("HY2-Salamander", func(o *Outbound) []any {
		return []any{o.Protocol, ProtoHysteria2, o.Password, "letmein", o.Hysteria2.Obfs, "salamander",
			o.Hysteria2.ObfsPassword, "gawrgura", o.Security.AllowInsecure, true, o.Security.SNI, "hy.example.com"}
	})
	check("HY2-Hopping", func(o *Outbound) []any {
		return []any{o.Server, "2001:db8::1", o.Port, 20000, o.Hysteria2.Ports, "20000-30000"}
	})
	check("TUIC-v5", func(o *Outbound) []any {
		return []any{o.UUID, "2dd61d93-75d8-4da4-ac0e-6aece7eac365", o.Password, "tuic-pass",
			o.TUIC.CongestionControl, "bbr", o.TUIC.UDPRelayMode, "native", o.Security.ALPN, []string{"h3"}}
	})
}

func TestEngineSelection(t *testing.T) {
	want := map[string]string{
		"TR-Istanbul Reality": EngineXray, "FR-XHTTP": EngineXray, "US-VMess-WS": EngineXray,
		"SS-AEAD": EngineXray, "SS-Plugin": EngineSingBox, "HY2-Salamander": EngineSingBox,
		"TUIC-v5": EngineSingBox,
	}
	for _, l := range fixtureLinks(t) {
		o, _ := ParseLink(l)
		if w, ok := want[o.Remark]; ok {
			got, err := o.Engine()
			if err != nil || got != w {
				t.Errorf("%s: engine %q err %v, want %q", o.Remark, got, err, w)
			}
		}
	}
	// allowInsecure on TLS can't go to Xray any more.
	o, _ := ParseLink("vless://8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b@a.example.com:443?security=tls&type=ws&allowInsecure=1#x")
	if e, _ := o.Engine(); e != EngineSingBox {
		t.Errorf("insecure ws should go to sing-box, got %s", e)
	}
	o, _ = ParseLink("vless://8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b@a.example.com:443?security=tls&type=xhttp&allowInsecure=1#x")
	if _, err := o.Engine(); err == nil {
		t.Error("insecure xhttp must be refused (no engine supports it)")
	}
}

func TestRoundTrip(t *testing.T) {
	for _, l := range fixtureLinks(t) {
		o, err := ParseLink(l)
		if err != nil {
			t.Fatal(err)
		}
		link, err := ToLink(o, false)
		if err != nil {
			t.Fatalf("%s: ToLink: %v", o.Remark, err)
		}
		o2, err := ParseLink(link)
		if err != nil {
			t.Fatalf("%s: reparse %q: %v", o.Remark, link, err)
		}
		if o.ID != o2.ID {
			t.Errorf("%s: id changed across round trip: %s -> %s (%s)", o.Remark, o.ID, o2.ID, link)
		}
		if o2.Remark != o.Remark {
			t.Errorf("remark %q -> %q", o.Remark, o2.Remark)
		}
	}
}

func TestStableIDIgnoresRemark(t *testing.T) {
	a, _ := ParseLink("trojan://pw@198.51.100.7:443?sni=t.example.com#One")
	b, _ := ParseLink("trojan://pw@198.51.100.7:443?sni=t.example.com#Two")
	c, _ := ParseLink("trojan://pw2@198.51.100.7:443?sni=t.example.com#One")
	if a.ID != b.ID {
		t.Error("remark must not change the id")
	}
	if a.ID == c.ID {
		t.Error("different credentials must change the id")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"http://example.com",
		"vless://@host:443",
		"vless://uuid@host",
		"vless://uuid@host:99999",
		"vmess://!!!notbase64",
		"ss://bm9wZQ@host:1",
		"wireguard://x@y:1",
	}
	for _, l := range bad {
		if _, err := ParseLink(l); err == nil {
			t.Errorf("ParseLink(%q) should fail", l)
		}
	}
}

func TestRedactedLink(t *testing.T) {
	for _, l := range fixtureLinks(t) {
		o, _ := ParseLink(l)
		s, err := ToLink(o, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{o.UUID, o.Password} {
			if secret != "" && strings.Contains(s, secret) {
				t.Errorf("%s: redacted link leaks a credential: %s", o.Remark, s)
			}
		}
	}
}

func TestParseImportFormats(t *testing.T) {
	links := fixtureLinks(t)
	plain := "# my list\n" + strings.Join(links, "\r\n") + "\nnot-a-link://x\n"
	res, err := ParseImport([]byte(plain), "sub1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outbounds) != len(links) || len(res.Errors) != 1 {
		t.Fatalf("plain: got %d outbounds, %d errors", len(res.Outbounds), len(res.Errors))
	}
	for _, o := range res.Outbounds {
		if o.Group != "sub1" {
			t.Fatal("group not stamped")
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		b64 := enc.EncodeToString([]byte(strings.Join(links, "\n")))
		res, err := ParseImport([]byte(b64[:40]+"\n"+b64[40:]), "")
		if err != nil || len(res.Outbounds) != len(links) {
			t.Fatalf("base64: %v (%d)", err, len(res.Outbounds))
		}
	}
	// Duplicate links collapse.
	res, _ = ParseImport([]byte(links[0]+"\n"+links[0]), "")
	if len(res.Outbounds) != 1 {
		t.Fatal("duplicates should collapse")
	}
}

func TestParseJSONImport(t *testing.T) {
	xray := `{"remarks":"Imported","outbounds":[
	  {"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"203.0.113.50","port":443,"users":[{"id":"8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b","encryption":"none"}]}]},
	   "streamSettings":{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/p"}}},
	  {"protocol":"freedom","tag":"direct"},{"protocol":"blackhole","tag":"block"}]}`
	obs, err := ParseJSONImport([]byte(xray))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Server != "203.0.113.50" || obs[0].Port != 443 || obs[0].Remark != "Imported" {
		t.Fatalf("xray import: %+v", obs)
	}
	if e, _ := obs[0].Engine(); e != EngineXray {
		t.Fatal("raw xray must use xray engine")
	}
	sb := `{"outbounds":[{"type":"hysteria2","tag":"hy","server":"hy.example.com","server_port":443,"password":"x"},{"type":"direct","tag":"direct"}]}`
	obs, err = ParseJSONImport([]byte(sb))
	if err != nil || len(obs) != 1 || obs[0].Protocol != "hysteria2" || obs[0].Port != 443 {
		t.Fatalf("sing-box import: %v %+v", err, obs)
	}
	if e, _ := obs[0].Engine(); e != EngineSingBox {
		t.Fatal("raw sing-box must use sing-box engine")
	}
	r := Redacted(obs[0])
	if strings.Contains(string(r.RawSingBox), `"x"`) {
		t.Fatalf("raw json not redacted: %s", r.RawSingBox)
	}
}

func TestSubUserInfo(t *testing.T) {
	u := ParseSubUserInfo("upload=100; download=2000; total=10737418240; expire=1767225600")
	if u.Upload != 100 || u.Download != 2000 || u.Total != 10737418240 || u.Expire != 1767225600 {
		t.Fatalf("%+v", u)
	}
}

func TestScrubber(t *testing.T) {
	var s Scrubber
	o, _ := ParseLink("trojan://super-secret-pw@198.51.100.7:443#t")
	s.SetFromOutbounds([]*Outbound{o})
	got := s.Scrub("dial failed for super-secret-pw user 8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b")
	if strings.Contains(got, "super-secret-pw") || strings.Contains(got, "8f2a1b3c") {
		t.Fatalf("not scrubbed: %s", got)
	}
}
