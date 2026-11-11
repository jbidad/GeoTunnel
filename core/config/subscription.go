package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Subscription is a remote list of outbounds.
type Subscription struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
	// RefreshMinutes is the periodic refresh interval; 0 disables it.
	RefreshMinutes int `json:"refreshMinutes,omitempty"`
	// Via is the outbound (or profile) id to fetch through; empty means direct.
	Via         string        `json:"via,omitempty"`
	LastUpdated int64         `json:"lastUpdated,omitempty"` // unix seconds
	LastError   string        `json:"lastError,omitempty"`
	UserInfo    *SubUserInfo  `json:"userInfo,omitempty"`
}

// SubUserInfo is the de-facto `subscription-userinfo` response header.
type SubUserInfo struct {
	Upload   int64 `json:"upload,omitempty"`
	Download int64 `json:"download,omitempty"`
	Total    int64 `json:"total,omitempty"`
	Expire   int64 `json:"expire,omitempty"`
}

// ParseSubUserInfo parses "upload=1; download=2; total=3; expire=4".
func ParseSubUserInfo(h string) *SubUserInfo {
	if h == "" {
		return nil
	}
	info := &SubUserInfo{}
	for _, part := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.ToLower(k) {
		case "upload":
			info.Upload = n
		case "download":
			info.Download = n
		case "total":
			info.Total = n
		case "expire":
			info.Expire = n
		}
	}
	return info
}

// ImportResult is what an import produced: the outbounds that parsed, and a
// per-line error list for the ones that did not (credentials never included).
type ImportResult struct {
	Outbounds []*Outbound `json:"outbounds"`
	Errors    []string    `json:"errors,omitempty"`
}

// ParseImport accepts anything a user might paste or a subscription might
// return: a single link, a newline list of links, a base64 blob of links, an
// Xray JSON config / outbound, or a sing-box JSON config. group is stamped on
// every outbound (subscription id, or "" for manual imports).
func ParseImport(body []byte, group string) (*ImportResult, error) {
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if len(body) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var res *ImportResult
	if body[0] == '{' || body[0] == '[' {
		obs, err := ParseJSONImport(body)
		if err != nil {
			return nil, err
		}
		res = &ImportResult{Outbounds: obs}
	} else {
		text := string(body)
		if !strings.Contains(text, "://") {
			dec, err := decodeBase64Loose(text)
			if err != nil {
				return nil, fmt.Errorf("input is neither share links, base64 nor JSON")
			}
			text = string(dec)
		}
		res = parseLinkLines(text)
	}
	seen := map[string]bool{}
	dedup := res.Outbounds[:0]
	for _, o := range res.Outbounds {
		o.Group = group
		if seen[o.ID] {
			continue
		}
		seen[o.ID] = true
		dedup = append(dedup, o)
	}
	res.Outbounds = dedup
	if len(res.Outbounds) == 0 {
		if len(res.Errors) > 0 {
			return res, fmt.Errorf("no outbound could be imported: %s", res.Errors[0])
		}
		return res, fmt.Errorf("no outbound found")
	}
	return res, nil
}

func parseLinkLines(text string) *ImportResult {
	res := &ImportResult{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		o, err := ParseLink(line)
		if err != nil {
			scheme, _, _ := strings.Cut(line, "://")
			res.Errors = append(res.Errors, fmt.Sprintf("line %d (%s): %v", i+1, scheme, err))
			continue
		}
		res.Outbounds = append(res.Outbounds, o)
	}
	return res
}

// ParseJSONImport handles Xray and sing-box JSON: a full config, a single
// outbound, an array of outbounds, or an array of full configs.
func ParseJSONImport(body []byte) ([]*Outbound, error) {
	var any_ any
	if err := json.Unmarshal(body, &any_); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	var out []*Outbound
	var walk func(v any, remark string) error
	walk = func(v any, remark string) error {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				if err := walk(e, remark); err != nil {
					return err
				}
			}
		case map[string]any:
			if obs, ok := x["outbounds"].([]any); ok {
				r, _ := x["remarks"].(string)
				for _, e := range obs {
					if err := walk(e, r); err != nil {
						return err
					}
				}
				return nil
			}
			ob, err := outboundFromJSON(x, remark)
			if err != nil {
				return err
			}
			if ob != nil {
				out = append(out, ob)
			}
		}
		return nil
	}
	if err := walk(any_, ""); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no proxy outbound found in JSON")
	}
	return out, nil
}

var nonProxyXray = map[string]bool{"freedom": true, "blackhole": true, "dns": true, "loopback": true}
var nonProxySingBox = map[string]bool{"direct": true, "block": true, "dns": true, "selector": true, "urltest": true}

func outboundFromJSON(m map[string]any, remark string) (*Outbound, error) {
	raw, _ := json.Marshal(m)
	tag, _ := m["tag"].(string)
	if proto, ok := m["protocol"].(string); ok { // Xray
		if nonProxyXray[proto] {
			return nil, nil
		}
		o := &Outbound{Protocol: proto, RawXray: raw, Remark: firstNonEmpty(remark, tag)}
		o.Server, o.Port = xrayServer(m)
		o.ID = StableID(o)
		if o.Remark == "" {
			o.Remark = proto + " " + o.Server
		}
		return o, nil
	}
	if typ, ok := m["type"].(string); ok { // sing-box
		if nonProxySingBox[typ] {
			return nil, nil
		}
		o := &Outbound{Protocol: typ, RawSingBox: raw, Remark: firstNonEmpty(tag, remark)}
		o.Server, _ = m["server"].(string)
		if p, ok := m["server_port"].(float64); ok {
			o.Port = int(p)
		}
		o.ID = StableID(o)
		if o.Remark == "" {
			o.Remark = typ + " " + o.Server
		}
		return o, nil
	}
	return nil, nil
}

func xrayServer(m map[string]any) (string, int) {
	settings, _ := m["settings"].(map[string]any)
	if settings == nil {
		return "", 0
	}
	pick := func(obj map[string]any) (string, int) {
		addr, _ := obj["address"].(string)
		port, _ := obj["port"].(float64)
		return addr, int(port)
	}
	if _, ok := settings["address"]; ok {
		return pick(settings)
	}
	for _, key := range []string{"vnext", "servers", "peers"} {
		if list, ok := settings[key].([]any); ok && len(list) > 0 {
			if first, ok := list[0].(map[string]any); ok {
				if key == "peers" {
					ep, _ := first["endpoint"].(string)
					if h, p, err := splitHostPort(ep); err == nil {
						return h, p
					}
					return ep, 0
				}
				return pick(first)
			}
		}
	}
	return "", 0
}
