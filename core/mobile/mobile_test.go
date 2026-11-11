package mobile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBindingSurface(t *testing.T) {
	res, err := ParseImport("trojan://pw@198.51.100.7:443#t\nvless://8f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b@203.0.113.1:443?security=reality&pbk=Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8L9z0X1c&sni=a.example.com#v", "")
	if err != nil {
		t.Fatal(err)
	}
	var r struct{ Outbounds []json.RawMessage }
	json.Unmarshal([]byte(res), &r)
	if len(r.Outbounds) != 2 {
		t.Fatalf("%s", res)
	}
	link, err := ToLink(string(r.Outbounds[0]), true)
	if err != nil || strings.Contains(link, "pw@") {
		t.Fatalf("%v %s", err, link)
	}
	var ob struct{ ID string }
	json.Unmarshal(r.Outbounds[1], &ob)
	state := `{"outbounds":[` + string(r.Outbounds[1]) + `],"profiles":[{"id":"w","outbound":"` + ob.ID + `","targets":[{"type":"webapp","value":"https://a.example.com/"}]}],"settings":{"platform":"android"}}`
	if err := ValidateState(state); err != nil {
		t.Fatal(err)
	}
	// Web-container-only state: no TUN, so no platform is required.
	if err := Start(state, nil); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	port, err := ProfilePort("w")
	if err != nil || port != 10801 {
		t.Fatalf("port %d %v", port, err)
	}
	if !strings.Contains(Stats(), `"running":true`) {
		t.Fatal(Stats())
	}
	UpdateDefaultInterface("wlan0", 3, "192.168.1.5/24", false, false)
	if sharedMonitor.DefaultInterface().Name != "wlan0" {
		t.Fatal("monitor not updated")
	}
}
