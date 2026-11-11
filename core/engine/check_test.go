package engine

import (
	"os"
	"strings"
	"testing"

	"geotunnel/core/config"
)

func fixtureOutbounds(t *testing.T) []*config.Outbound {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/links.txt")
	if err != nil {
		t.Fatal(err)
	}
	var obs []*config.Outbound
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		o, err := config.ParseLink(l)
		if err != nil {
			t.Fatal(err)
		}
		obs = append(obs, o)
	}
	return obs
}

// TestEveryFixtureBuildsValidCoreConfigs feeds each fixture outbound through
// the real Xray-core and sing-box config loaders, so a schema change in
// either pinned core fails here rather than on a device.
func TestEveryFixtureBuildsValidCoreConfigs(t *testing.T) {
	for _, o := range fixtureOutbounds(t) {
		o := o
		t.Run(o.Remark, func(t *testing.T) {
			st := &config.State{
				Outbounds: []*config.Outbound{o},
				Profiles:  []*config.Profile{{ID: "p", Outbound: o.ID}},
			}
			if err := st.Normalize(); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build(st, allocXrayInbound)
			if err != nil {
				t.Fatal(err)
			}
			if len(built.Warnings) > 0 {
				t.Fatalf("warnings: %v", built.Warnings)
			}
			eng, _ := o.Engine()
			if eng == config.EngineXray {
				if built.Xray == nil {
					t.Fatal("expected an Xray config")
				}
				if err := CheckXray(built.Xray); err != nil {
					t.Fatalf("xray rejects config: %v\n%s", err, built.Xray)
				}
			}
			if err := CheckSingBox(built.SingBox); err != nil {
				t.Fatalf("sing-box rejects config: %v\n%s", err, built.SingBox)
			}
		})
	}
}

// TestTunConfigsParse checks the full routing config (TUN, per-app rules,
// remote DNS, kill switch) for every platform's target types.
func TestTunConfigsParse(t *testing.T) {
	obs := fixtureOutbounds(t)
	for _, o := range obs[:2] {
		o.Group = "sub1"
	}
	for _, platform := range []string{"android", "linux", "darwin", "windows", "ios"} {
		platform := platform
		t.Run(platform, func(t *testing.T) {
			var targets []config.Target
			switch platform {
			case "android":
				targets = []config.Target{{Type: config.TargetAndroidPackage, Value: "com.example.app"}}
			case "ios":
				targets = []config.Target{{Type: config.TargetDevice}}
			default:
				targets = []config.Target{{Type: config.TargetProcess, Value: "firefox"}, {Type: config.TargetProcessPath, Value: "/usr/bin/curl"}}
			}
			st := &config.State{
				Outbounds: obs,
				Profiles: []*config.Profile{
					{ID: "tr", Outbound: obs[0].ID, Targets: targets},
					{ID: "grp", Outbound: "group:sub1:fastest", Targets: []config.Target{{Type: config.TargetWebApp, Value: "https://app.example.com/"}}},
					{ID: "dead", Outbound: "ob-gone", Targets: []config.Target{{Type: config.TargetWebApp, Value: "https://x.example.com/"}}},
				},
				Settings: config.Settings{Platform: platform, TUN: config.TUN{Enabled: true}},
			}
			if err := st.Normalize(); err != nil {
				t.Fatal(err)
			}
			built, err := config.Build(st, allocXrayInbound)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(built.SingBox), `"type": "tun"`) {
				t.Fatal("tun inbound missing")
			}
			if err := CheckSingBox(built.SingBox); err != nil {
				t.Fatalf("sing-box rejects %s config: %v\n%s", platform, err, built.SingBox)
			}
			if err := CheckXray(built.Xray); err != nil {
				t.Fatalf("xray: %v", err)
			}
		})
	}
}
