package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/text/language"
)

// Target types a profile can apply to.
const (
	TargetAndroidPackage = "android_package"
	TargetProcess        = "process"      // executable name, e.g. Example.exe / firefox
	TargetProcessPath    = "process_path" // absolute executable path
	TargetWebApp         = "webapp"       // URL opened in GeoTunnel's own container
	TargetDevice         = "device"       // whole-device tunnel (iOS, or Android full VPN)
)

// Auto is the sentinel for values derived from the exit IP.
const Auto = "auto"

// Profile ties a set of apps to one exit location.
type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Outbound is an outbound id, or "group:<subscription-id>:fastest".
	Outbound string     `json:"outbound"`
	Timezone string     `json:"timezone"` // "auto" or IANA zone
	Geo      GeoSetting `json:"geo"`
	Language string     `json:"language"` // "auto" or BCP 47 tag
	DNS      string     `json:"dns"`      // only "remote" is supported
	WebRTC   string     `json:"webrtc"`   // "disable" | "proxy-only"
	Targets  []Target   `json:"targets"`
	// LocalPort is the SOCKS5/HTTP inbound for this profile (web container,
	// "launch with profile"). 0 = assign automatically.
	LocalPort int  `json:"localPort,omitempty"`
	Disabled  bool `json:"disabled,omitempty"`
}

// Target is one app (or the whole device) a profile applies to.
type Target struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// GeoSetting is either "auto" or fixed coordinates. It accepts the three
// JSON spellings seen in the spec: "auto", an object, or a string holding a
// JSON object.
type GeoSetting struct {
	Auto      bool    `json:"-"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	AccuracyM float64 `json:"accuracyM,omitempty"`
}

// IsUnset reports a zero GeoSetting, which means "auto": (0,0) is never a
// meaningful manual location.
func (g GeoSetting) IsUnset() bool { return g.Lat == 0 && g.Lon == 0 && g.AccuracyM == 0 }

func (g GeoSetting) MarshalJSON() ([]byte, error) {
	if g.Auto || g.IsUnset() {
		return []byte(`"auto"`), nil
	}
	type plain GeoSetting
	return json.Marshal(plain(g))
}

func (g *GeoSetting) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*g = GeoSetting{Auto: true}
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		s = strings.TrimSpace(s)
		if s == "" || s == Auto {
			*g = GeoSetting{Auto: true}
			return nil
		}
		b = []byte(s)
	}
	type plain GeoSetting
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("geo: want \"auto\" or {lat,lon,accuracyM}: %w", err)
	}
	*g = GeoSetting(p)
	return nil
}

// State is everything the UI hands to the core.
type State struct {
	Version       int             `json:"version"`
	Outbounds     []*Outbound     `json:"outbounds"`
	Subscriptions []*Subscription `json:"subscriptions,omitempty"`
	Profiles      []*Profile      `json:"profiles"`
	Settings      Settings        `json:"settings"`
}

// Settings are global core options.
type Settings struct {
	// Platform: android, ios, linux, darwin, windows. Decides which target
	// types and TUN options apply.
	Platform string `json:"platform"`
	BasePort int    `json:"basePort,omitempty"` // first profile inbound port, default 10801
	LogLevel string `json:"logLevel,omitempty"` // trace|debug|info|warn|error
	TUN      TUN    `json:"tun"`
	// RemoteDNS is the resolver tunneled apps use, reached through their
	// profile's outbound. Default https://1.1.1.1/dns-query.
	RemoteDNS string `json:"remoteDns,omitempty"`
	// TestURL is used for latency tests and "fastest" groups.
	TestURL string `json:"testUrl,omitempty"`
}

// TUN controls the system tunnel used for native apps.
type TUN struct {
	Enabled bool   `json:"enabled"`
	MTU     int    `json:"mtu,omitempty"`
	Stack   string `json:"stack,omitempty"` // system | gvisor | mixed
}

const (
	DefaultBasePort  = 10801
	DefaultRemoteDNS = "https://1.1.1.1/dns-query"
	DefaultTestURL   = "https://www.gstatic.com/generate_204"
)

// ParseState decodes and validates a State document.
func ParseState(b []byte) (*State, error) {
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	if err := s.Normalize(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Normalize fills defaults, validates every profile and assigns ports.
func (s *State) Normalize() error {
	if s.Settings.BasePort == 0 {
		s.Settings.BasePort = DefaultBasePort
	}
	if s.Settings.RemoteDNS == "" {
		s.Settings.RemoteDNS = DefaultRemoteDNS
	}
	if s.Settings.TestURL == "" {
		s.Settings.TestURL = DefaultTestURL
	}
	if s.Settings.LogLevel == "" {
		s.Settings.LogLevel = "info"
	}
	ids := map[string]bool{}
	for _, p := range s.Profiles {
		if p.ID == "" {
			return fmt.Errorf("profile %q: missing id", p.Name)
		}
		if ids[p.ID] {
			return fmt.Errorf("duplicate profile id %q", p.ID)
		}
		ids[p.ID] = true
		if err := p.Validate(s.Settings.Platform); err != nil {
			return fmt.Errorf("profile %q: %w", p.ID, err)
		}
	}
	return AssignPorts(s.Profiles, s.Settings.BasePort)
}

// Validate checks one profile.
func (p *Profile) Validate(platform string) error {
	if p.Timezone == "" {
		p.Timezone = Auto
	}
	if p.Language == "" {
		p.Language = Auto
	}
	if p.DNS == "" {
		p.DNS = "remote"
	}
	if p.WebRTC == "" {
		p.WebRTC = "disable"
	}
	if p.Geo.IsUnset() {
		p.Geo.Auto = true
	}
	if p.Timezone != Auto {
		if _, err := time.LoadLocation(p.Timezone); err != nil || p.Timezone == "Local" {
			return fmt.Errorf("unknown IANA time zone %q", p.Timezone)
		}
	}
	if p.Language != Auto {
		if _, err := language.Parse(p.Language); err != nil {
			return fmt.Errorf("invalid language tag %q", p.Language)
		}
	}
	if p.DNS != "remote" {
		return fmt.Errorf("dns %q not supported (only \"remote\": tunneled apps must not resolve locally)", p.DNS)
	}
	switch p.WebRTC {
	case "disable", "proxy-only":
	default:
		return fmt.Errorf("webrtc must be \"disable\" or \"proxy-only\"")
	}
	if !p.Geo.Auto {
		if p.Geo.Lat < -90 || p.Geo.Lat > 90 || p.Geo.Lon < -180 || p.Geo.Lon > 180 {
			return fmt.Errorf("geo out of range")
		}
		if p.Geo.AccuracyM <= 0 {
			p.Geo.AccuracyM = 3000
		}
	}
	for _, t := range p.Targets {
		if t.Value == "" && t.Type != TargetDevice {
			return fmt.Errorf("target %s: empty value", t.Type)
		}
		if reason := TargetUnsupported(t.Type, platform); reason != "" {
			return fmt.Errorf("target %s on %s: %s", t.Type, platform, reason)
		}
	}
	return nil
}

// TargetUnsupported returns why a target type cannot be tunneled on a
// platform, or "" when it can. Keeps unsupported capabilities explicit.
func TargetUnsupported(typ, platform string) string {
	switch typ {
	case TargetWebApp:
		return ""
	case TargetDevice:
		if platform == "android" || platform == "ios" || platform == "" {
			return ""
		}
		return "whole-device routing on desktop is not offered; pick processes instead"
	case TargetAndroidPackage:
		if platform == "android" || platform == "" {
			return ""
		}
		return "android packages exist only on Android"
	case TargetProcess, TargetProcessPath:
		switch platform {
		case "linux", "darwin", "windows", "":
			return ""
		case "ios":
			return "iOS has no per-app VPN for consumer apps (needs MDM)"
		default:
			return "use android_package on Android"
		}
	}
	return "unknown target type"
}

// AssignPorts keeps valid, unique LocalPorts and assigns the lowest free
// port >= base to the rest, in profile-id order so results are stable.
func AssignPorts(profiles []*Profile, base int) error {
	used := map[int]bool{}
	for _, p := range profiles {
		if p.LocalPort > 0 && p.LocalPort < 65536 && !used[p.LocalPort] {
			used[p.LocalPort] = true
		} else {
			p.LocalPort = 0
		}
	}
	sorted := append([]*Profile(nil), profiles...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	next := base
	for _, p := range sorted {
		if p.LocalPort != 0 {
			continue
		}
		for used[next] {
			next++
		}
		if next > 65535 {
			return fmt.Errorf("ran out of local ports")
		}
		p.LocalPort = next
		used[next] = true
	}
	return nil
}

// OutboundByID finds an outbound.
func (s *State) OutboundByID(id string) *Outbound {
	for _, o := range s.Outbounds {
		if o.ID == id {
			return o
		}
	}
	return nil
}

// ProfileByID finds a profile.
func (s *State) ProfileByID(id string) *Profile {
	for _, p := range s.Profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// ResolveOutbounds returns the outbounds a profile may use. For
// "group:<sub>:fastest" that is every outbound of the subscription; an empty
// result means the profile has nothing to exit through and must be blocked.
func (s *State) ResolveOutbounds(p *Profile) (members []*Outbound, group bool) {
	if rest, ok := strings.CutPrefix(p.Outbound, "group:"); ok {
		sub, _, _ := strings.Cut(rest, ":")
		for _, o := range s.Outbounds {
			if o.Group == sub {
				members = append(members, o)
			}
		}
		return members, true
	}
	if o := s.OutboundByID(p.Outbound); o != nil {
		return []*Outbound{o}, false
	}
	return nil, false
}
