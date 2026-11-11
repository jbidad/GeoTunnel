// Package config holds GeoTunnel's app-level data model (outbounds, profiles,
// settings), the share-link / subscription parsers, and the builders that turn
// that model into Xray-core and sing-box JSON.
package config

import (
	"encoding/json"
	"fmt"
)

// Protocol names used in Outbound.Protocol.
const (
	ProtoVLESS       = "vless"
	ProtoVMess       = "vmess"
	ProtoTrojan      = "trojan"
	ProtoShadowsocks = "shadowsocks"
	ProtoHysteria2   = "hysteria2"
	ProtoTUIC        = "tuic"
)

// Engine names: which core runs an outbound.
const (
	EngineXray    = "xray"
	EngineSingBox = "singbox"
)

// Outbound is one v2ray-family server, normalised from whatever it was
// imported from. Credentials live in UUID / Password; never log those.
type Outbound struct {
	ID       string `json:"id"`
	Remark   string `json:"remark"`
	Group    string `json:"group,omitempty"` // subscription id, empty for manual imports
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     int    `json:"port"`

	UUID       string `json:"uuid,omitempty"`       // vless, vmess, tuic
	Password   string `json:"password,omitempty"`   // trojan, shadowsocks, hysteria2, tuic
	Method     string `json:"method,omitempty"`     // shadowsocks cipher; vmess "security"
	AlterID    int    `json:"alterId,omitempty"`    // vmess legacy
	Flow       string `json:"flow,omitempty"`       // vless flow, e.g. xtls-rprx-vision
	Encryption string `json:"encryption,omitempty"` // vless encryption ("none" or ML-KEM string)
	Plugin     string `json:"plugin,omitempty"`     // shadowsocks SIP003 plugin name
	PluginOpts string `json:"pluginOpts,omitempty"` // shadowsocks plugin options

	Transport Transport `json:"transport"`
	Security  Security  `json:"security"`

	Hysteria2 *Hysteria2Options `json:"hysteria2,omitempty"`
	TUIC      *TUICOptions      `json:"tuic,omitempty"`

	// RawXray / RawSingBox hold a verbatim outbound object for advanced JSON
	// imports. When set, builders emit it (with the tag replaced) instead of
	// generating one from the fields above.
	RawXray    json.RawMessage `json:"rawXray,omitempty"`
	RawSingBox json.RawMessage `json:"rawSingBox,omitempty"`

	// Status fields filled in by the app after tests.
	LastLatencyMs int    `json:"lastLatencyMs,omitempty"`
	LastExitIP    string `json:"lastExitIp,omitempty"`
	LastCountry   string `json:"lastCountry,omitempty"`
}

// Transport describes the stream layer.
type Transport struct {
	// Type: tcp (raw), ws, grpc, httpupgrade, xhttp, h2, kcp, quic.
	Type        string          `json:"type"`
	Host        string          `json:"host,omitempty"`
	Path        string          `json:"path,omitempty"`
	ServiceName string          `json:"serviceName,omitempty"` // grpc
	Authority   string          `json:"authority,omitempty"`   // grpc
	Mode        string          `json:"mode,omitempty"`        // grpc gun/multi, xhttp mode
	HeaderType  string          `json:"headerType,omitempty"`  // tcp "http", kcp header
	Seed        string          `json:"seed,omitempty"`        // kcp
	Extra       json.RawMessage `json:"extra,omitempty"`       // xhttp extra object
}

// Security describes the TLS layer.
type Security struct {
	Type          string   `json:"type"` // none, tls, reality
	SNI           string   `json:"sni,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
	Fingerprint   string   `json:"fp,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
	PublicKey     string   `json:"pbk,omitempty"` // reality
	ShortID       string   `json:"sid,omitempty"` // reality
	SpiderX       string   `json:"spx,omitempty"` // reality
	ECH           string   `json:"ech,omitempty"`
	PinSHA256     string   `json:"pinSHA256,omitempty"`
}

// Hysteria2Options holds the hysteria2-only fields.
type Hysteria2Options struct {
	Obfs         string `json:"obfs,omitempty"` // "salamander"
	ObfsPassword string `json:"obfsPassword,omitempty"`
	Ports        string `json:"ports,omitempty"` // port hopping, e.g. "20000-30000"
	UpMbps       int    `json:"upMbps,omitempty"`
	DownMbps     int    `json:"downMbps,omitempty"`
}

// TUICOptions holds the tuic-only fields.
type TUICOptions struct {
	CongestionControl string `json:"congestionControl,omitempty"`
	UDPRelayMode      string `json:"udpRelayMode,omitempty"`
	ZeroRTT           bool   `json:"zeroRtt,omitempty"`
}

// Engine reports which core should run this outbound. Xray-core is preferred
// for the v2ray family (widest transport coverage, incl. XHTTP and REALITY);
// sing-box runs what current Xray-core no longer supports. The rules below
// were checked against the pinned versions (see docs/core-versions.md):
//   - Xray removed the "h2"/"http" and "quic" transports (infra/conf
//     TransportProtocol.Build returns PrintRemovedFeatureError).
//   - Xray rejects tlsSettings.allowInsecure after 2026-06-01; only a pinned
//     certificate hash (pinnedPeerCertSha256) is accepted instead.
//   - Xray has no SIP003 plugin support; sing-box has obfs-local/v2ray-plugin.
//   - sing-box has no XHTTP transport.
func (o *Outbound) Engine() (string, error) {
	if len(o.RawXray) > 0 {
		return EngineXray, nil
	}
	if len(o.RawSingBox) > 0 {
		return EngineSingBox, nil
	}
	switch o.Protocol {
	case ProtoHysteria2, ProtoTUIC:
		return EngineSingBox, nil
	case ProtoShadowsocks:
		if o.Plugin != "" {
			return EngineSingBox, nil
		}
	}
	switch o.Transport.Type {
	case "h2", "http", "quic":
		return EngineSingBox, nil
	}
	if o.Security.AllowInsecure && o.Security.PinSHA256 == "" && o.Security.Type == "tls" {
		switch o.Transport.Type {
		case "xhttp", "kcp":
			return "", fmt.Errorf("%s over %s with allowInsecure: Xray-core no longer accepts allowInsecure and sing-box has no %s transport; ask the provider for a pinned certificate hash (pcs=)", o.Protocol, o.Transport.Type, o.Transport.Type)
		}
		return EngineSingBox, nil
	}
	return EngineXray, nil
}

// Validate checks the fields a builder needs.
func (o *Outbound) Validate() error {
	if len(o.RawXray) > 0 || len(o.RawSingBox) > 0 {
		return nil
	}
	if o.Server == "" {
		return fmt.Errorf("%s: missing server", o.Protocol)
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("%s: invalid port %d", o.Protocol, o.Port)
	}
	switch o.Protocol {
	case ProtoVLESS, ProtoVMess:
		if o.UUID == "" {
			return fmt.Errorf("%s: missing id", o.Protocol)
		}
	case ProtoTrojan, ProtoHysteria2:
		if o.Password == "" {
			return fmt.Errorf("%s: missing password", o.Protocol)
		}
	case ProtoShadowsocks:
		if o.Method == "" || o.Password == "" {
			return fmt.Errorf("shadowsocks: missing method or password")
		}
	case ProtoTUIC:
		if o.UUID == "" {
			return fmt.Errorf("tuic: missing uuid")
		}
	default:
		return fmt.Errorf("unsupported protocol %q", o.Protocol)
	}
	return nil
}
