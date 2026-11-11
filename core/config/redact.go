package config

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// RedactedPlaceholder replaces credentials in logs and exports.
const RedactedPlaceholder = "REDACTED"

var uuidRe = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

// secretKeys are JSON keys whose values are credentials in Xray / sing-box
// outbound objects.
var secretKeys = map[string]bool{
	"id": true, "uuid": true, "password": true, "auth_str": true, "auth": true,
	"private_key": true, "privateKey": true, "pre_shared_key": true, "preSharedKey": true,
	"secretKey": true, "obfs-password": true, "obfsPassword": true,
}

// Redacted returns a copy of o with every credential replaced.
func Redacted(o *Outbound) Outbound {
	c := *o
	if c.UUID != "" {
		c.UUID = RedactedPlaceholder
	}
	if c.Password != "" {
		c.Password = RedactedPlaceholder
	}
	if c.Hysteria2 != nil {
		h := *c.Hysteria2
		if h.ObfsPassword != "" {
			h.ObfsPassword = RedactedPlaceholder
		}
		c.Hysteria2 = &h
	}
	c.RawXray = redactJSON(c.RawXray)
	c.RawSingBox = redactJSON(c.RawSingBox)
	return c
}

// RedactJSONConfig scrubs credential-looking keys from any JSON document
// (generated Xray / sing-box configs, raw imports) before it is logged or
// exported.
func RedactJSONConfig(b []byte) []byte { return redactJSON(b) }

func redactJSON(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return b
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return json.RawMessage(`"` + RedactedPlaceholder + `"`)
	}
	out, _ := json.Marshal(redactValue(v))
	return out
}

func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if _, isStr := val.(string); isStr && secretKeys[k] {
				x[k] = RedactedPlaceholder
				continue
			}
			x[k] = redactValue(val)
		}
	case []any:
		for i := range x {
			x[i] = redactValue(x[i])
		}
	case string:
		return uuidRe.ReplaceAllString(x, RedactedPlaceholder)
	}
	return v
}

// Scrubber removes known secrets and anything UUID-shaped from log lines. It
// is safe for concurrent use.
type Scrubber struct {
	mu      sync.RWMutex
	secrets []string // sorted longest first so overlapping secrets scrub fully
}

// SetFromOutbounds registers every credential of the given outbounds.
func (s *Scrubber) SetFromOutbounds(obs []*Outbound) {
	var list []string
	add := func(v string) {
		if len(v) >= 4 && v != RedactedPlaceholder {
			list = append(list, v)
		}
	}
	for _, o := range obs {
		add(o.UUID)
		add(o.Password)
		if o.Hysteria2 != nil {
			add(o.Hysteria2.ObfsPassword)
		}
		collectSecrets(o.RawXray, add)
		collectSecrets(o.RawSingBox, add)
	}
	s.SetSecrets(list)
}

// SetSecrets replaces the registered secret list.
func (s *Scrubber) SetSecrets(list []string) {
	sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) })
	s.mu.Lock()
	s.secrets = list
	s.mu.Unlock()
}

// Scrub returns line with secrets removed.
func (s *Scrubber) Scrub(line string) string {
	s.mu.RLock()
	for _, sec := range s.secrets {
		if strings.Contains(line, sec) {
			line = strings.ReplaceAll(line, sec, RedactedPlaceholder)
		}
	}
	s.mu.RUnlock()
	return uuidRe.ReplaceAllString(line, RedactedPlaceholder)
}

func collectSecrets(b json.RawMessage, add func(string)) {
	if len(b) == 0 {
		return
	}
	var v any
	if json.Unmarshal(b, &v) != nil {
		return
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				if s, ok := val.(string); ok && secretKeys[k] {
					add(s)
				} else {
					walk(val)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
}
