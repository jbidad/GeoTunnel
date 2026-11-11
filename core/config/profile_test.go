package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGeoSettingSpellings(t *testing.T) {
	cases := map[string]GeoSetting{
		`"auto"`: {Auto: true},
		`null`:   {Auto: true},
		`{"lat":41.01,"lon":28.97,"accuracyM":3000}`:              {Lat: 41.01, Lon: 28.97, AccuracyM: 3000},
		`"{\"lat\": 41.01, \"lon\": 28.97, \"accuracyM\": 3000}"`: {Lat: 41.01, Lon: 28.97, AccuracyM: 3000},
	}
	for in, want := range cases {
		var g GeoSetting
		if err := json.Unmarshal([]byte(in), &g); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if g != want {
			t.Errorf("%s: got %+v want %+v", in, g, want)
		}
	}
	for _, g := range []GeoSetting{{Auto: true}, {}} {
		b, _ := json.Marshal(g)
		if string(b) != `"auto"` {
			t.Errorf("%+v marshals as %s", g, b)
		}
	}
	p := Profile{ID: "x"}
	if err := p.Validate(""); err != nil || !p.Geo.Auto {
		t.Errorf("omitted geo must mean auto: %v %+v", err, p.Geo)
	}
}

const specProfile = `{
  "id": "tr-1",
  "name": "Turkey",
  "outbound": "group:sub1:fastest",
  "timezone": "auto",
  "geo": "{\"lat\": 41.01, \"lon\": 28.97, \"accuracyM\": 3000}",
  "language": "auto",
  "dns": "remote",
  "webrtc": "disable",
  "targets": [
    { "type": "android_package", "value": "com.example.app" },
    { "type": "webapp", "value": "https://app.example.com/" }
  ]
}`

func TestSpecProfileParses(t *testing.T) {
	var p Profile
	if err := json.Unmarshal([]byte(specProfile), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate("android"); err != nil {
		t.Fatal(err)
	}
	if p.Geo.Auto || p.Geo.Lat != 41.01 {
		t.Fatalf("geo: %+v", p.Geo)
	}
	// The spec example also lists a Windows process; that target is invalid on Android.
	p.Targets = append(p.Targets, Target{Type: TargetProcess, Value: "Example.exe"})
	if err := p.Validate("android"); err == nil {
		t.Fatal("process target must be rejected on android")
	}
	if err := p.Validate(""); err != nil { // platform-agnostic storage accepts all
		t.Fatal(err)
	}
}

func TestProfileValidation(t *testing.T) {
	bad := []Profile{
		{ID: "a", Timezone: "Mars/Olympus"},
		{ID: "a", Timezone: "Local"},
		{ID: "a", Language: "not a tag!"},
		{ID: "a", DNS: "local"},
		{ID: "a", WebRTC: "allow"},
		{ID: "a", Geo: GeoSetting{Lat: 100, Lon: 0}},
		{ID: "a", Targets: []Target{{Type: TargetProcess, Value: "x"}}},
	}
	for i, p := range bad {
		p := p
		if err := p.Validate("ios"); err == nil {
			t.Errorf("case %d should fail: %+v", i, p)
		}
	}
	ok := Profile{ID: "ok", Timezone: "Europe/Istanbul", Language: "tr-TR", Geo: GeoSetting{Lat: 41, Lon: 29}}
	if err := ok.Validate("linux"); err != nil {
		t.Fatal(err)
	}
	if ok.Geo.AccuracyM != 3000 {
		t.Error("default accuracy not filled")
	}
}

func TestAssignPorts(t *testing.T) {
	ps := []*Profile{{ID: "c"}, {ID: "a", LocalPort: 10801}, {ID: "b"}, {ID: "d", LocalPort: 10801}}
	if err := AssignPorts(ps, 10801); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, p := range ps {
		got[p.ID] = p.LocalPort
	}
	want := map[string]int{"a": 10801, "b": 10802, "c": 10803, "d": 10804}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: port %d want %d", k, got[k], v)
		}
	}
}

func testState(t *testing.T, platform string) *State {
	t.Helper()
	var obs []*Outbound
	for _, l := range fixtureLinks(t) {
		o, err := ParseLink(l)
		if err != nil {
			t.Fatal(err)
		}
		obs = append(obs, o)
	}
	obs[0].Group, obs[1].Group = "sub1", "sub1"
	s := &State{
		Outbounds: obs,
		Profiles: []*Profile{
			{ID: "tr", Outbound: obs[0].ID, Targets: []Target{{Type: TargetAndroidPackage, Value: "com.example.app"}, {Type: TargetProcess, Value: "Example.exe"}}},
			{ID: "grp", Outbound: "group:sub1:fastest", Targets: []Target{{Type: TargetAndroidPackage, Value: "org.example.other"}}},
			{ID: "dead", Outbound: "ob-doesnotexist", Targets: []Target{{Type: TargetAndroidPackage, Value: "com.example.dead"}}},
			{ID: "hy", Outbound: obs[14].ID, Targets: []Target{{Type: TargetWebApp, Value: "https://app.example.com/"}}},
		},
		Settings: Settings{Platform: platform, TUN: TUN{Enabled: true}},
	}
	if platform != "" && platform != "android" {
		for _, p := range s.Profiles {
			var keep []Target
			for _, tg := range p.Targets {
				if tg.Type != TargetAndroidPackage {
					keep = append(keep, tg)
				}
			}
			p.Targets = keep
		}
	}
	if platform == "android" {
		s.Profiles[0].Targets = s.Profiles[0].Targets[:1]
	}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBuildSingBoxAndroid(t *testing.T) {
	s := testState(t, "android")
	xin := map[string]XrayInbound{}
	for i, o := range XrayOutbounds(s) {
		xin[o.ID] = XrayInbound{OutboundID: o.ID, Port: 20000 + i, User: "u", Pass: "p"}
	}
	res, err := BuildSingBox(s, xin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(res.Config)
	if res.ProfileOutbound["dead"] != "" {
		t.Error("profile without outbound must be blocked")
	}
	if res.ProfileOutbound["grp"] != "p-grp" {
		t.Error("group profile should use urltest")
	}
	for _, want := range []string{
		`"include_package": [`, `"com.example.app"`, `"org.example.other"`, `"com.example.dead"`,
		`"type": "urltest"`, `"type": "hysteria2"`, `"action": "hijack-dns"`, `"action": "reject"`,
		`"tag": "dns-tr"`, `"detour": "` + s.Profiles[0].Outbound + `"`, `"listen_port": 10801`,
		`"strict_route": true`, `"fdfe:dcba:9876::1/126"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %s", want)
		}
	}
	if strings.Contains(cfg, `"Example.exe"`) {
		t.Error("process targets must not appear on android")
	}
}

func TestBuildXrayFailClosed(t *testing.T) {
	s := testState(t, "linux")
	var ins []XrayInbound
	for i, o := range XrayOutbounds(s) {
		ins = append(ins, XrayInbound{OutboundID: o.ID, Port: 20000 + i, User: "u", Pass: "p"})
	}
	b, err := BuildXray(s.Outbounds, ins, "info")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct{ Tag, Protocol string } `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Outbounds[0].Protocol != "blackhole" {
		t.Fatal("first (default) Xray outbound must be the blackhole")
	}
}
