package webapp

import (
	_ "embed"
	"strings"
)

//go:embed leakprobe.js
var leakProbe string

// DefaultEchoURL returns request headers as JSON with CORS enabled.
const DefaultEchoURL = "https://httpbin.org/headers"

// LeakProbe returns the read-only probe expression with the header-echo URL
// filled in (echoURL "" = DefaultEchoURL).
func LeakProbe(echoURL string) string {
	if echoURL == "" {
		echoURL = DefaultEchoURL
	}
	return strings.ReplaceAll(leakProbe, "__ECHO_URL__", strings.ReplaceAll(echoURL, "'", "%27"))
}
