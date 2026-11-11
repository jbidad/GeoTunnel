package geo

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Derived is what a profile ends up presenting.
type Derived struct {
	IP        string   `json:"ip"`
	Country   string   `json:"country"`
	Timezone  string   `json:"timezone"`
	Lat       float64  `json:"lat"`
	Lon       float64  `json:"lon"`
	AccuracyM float64  `json:"accuracyM"`
	Language  string   `json:"language"`  // BCP 47, e.g. tr-TR
	Languages []string `json:"languages"` // navigator.languages / Accept-Language order
	// Fixed fields are the ones the profile pinned (not "auto").
	Source string `json:"source"` // provider name, or "manual"
}

// Overrides are the profile's non-auto values.
type Overrides struct {
	Timezone string // "" or "auto" = derive
	Language string
	Geo      *[3]float64 // lat, lon, accuracyM; nil = derive
}

// Derive combines a lookup with the profile's fixed values. jitter moves the
// derived coordinates 1–3 km so many users of one exit don't share a point;
// pass the profile's session Jitter so the offset stays fixed per session.
func Derive(info *Info, ov Overrides, j Jitter) Derived {
	d := Derived{Source: "manual"}
	if info != nil {
		d.IP, d.Country, d.Source = info.IP, info.Country, info.Provider
	}
	if ov.Timezone != "" && ov.Timezone != "auto" {
		d.Timezone = ov.Timezone
	} else if info != nil {
		d.Timezone = info.Timezone
	}
	if d.Timezone == "" {
		d.Timezone = "UTC"
	}
	if ov.Geo != nil {
		d.Lat, d.Lon, d.AccuracyM = ov.Geo[0], ov.Geo[1], ov.Geo[2]
	} else if info != nil {
		d.Lat, d.Lon = j.Apply(info.Lat, info.Lon)
		d.AccuracyM = 3000
	}
	if ov.Language != "" && ov.Language != "auto" {
		d.Language = ov.Language
	} else {
		d.Language = CountryLanguage(d.Country)
	}
	d.Languages = LanguageList(d.Language)
	return d
}

// LanguageList expands "tr-TR" to ["tr-TR", "tr"], the shape browsers send.
func LanguageList(tag string) []string {
	base, _, ok := strings.Cut(tag, "-")
	if !ok || base == tag {
		return []string{tag}
	}
	return []string{tag, base}
}

// AcceptLanguage renders an Accept-Language header with q-values, e.g.
// ["tr-TR","tr"] -> "tr-TR,tr;q=0.9".
func AcceptLanguage(langs []string) string {
	parts := make([]string, 0, len(langs))
	for i, l := range langs {
		if i == 0 {
			parts = append(parts, l)
			continue
		}
		q := math.Max(0.1, 1.0-0.1*float64(i))
		parts = append(parts, l+";q="+strconv.FormatFloat(q, 'f', 1, 64))
	}
	return strings.Join(parts, ",")
}

// Jitter is a fixed random offset (bearing + 1–3 km distance).
type Jitter struct {
	BearingRad float64
	DistanceM  float64
}

// NewJitter draws a fresh offset.
func NewJitter() Jitter {
	var b [16]byte
	_, _ = rand.Read(b[:])
	u1 := float64(binary.LittleEndian.Uint64(b[:8])) / float64(math.MaxUint64)
	u2 := float64(binary.LittleEndian.Uint64(b[8:])) / float64(math.MaxUint64)
	return Jitter{BearingRad: u1 * 2 * math.Pi, DistanceM: 1000 + u2*2000}
}

// Apply moves (lat, lon) by the offset.
func (j Jitter) Apply(lat, lon float64) (float64, float64) {
	if j.DistanceM == 0 {
		return lat, lon
	}
	const mPerDegLat = 111320.0
	dLat := j.DistanceM * math.Cos(j.BearingRad) / mPerDegLat
	cos := math.Cos(lat * math.Pi / 180)
	if math.Abs(cos) < 1e-6 {
		cos = 1e-6
	}
	dLon := j.DistanceM * math.Sin(j.BearingRad) / (mPerDegLat * cos)
	lat2 := math.Max(-90, math.Min(90, lat+dLat))
	lon2 := math.Mod(lon+dLon+540, 360) - 180
	return round6(lat2), round6(lon2)
}

func round6(f float64) float64 { return math.Round(f*1e6) / 1e6 }

// DistanceM is the haversine distance between two points, in metres.
func DistanceM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371000.0
	rad := math.Pi / 180
	dLat := (lat2 - lat1) * rad
	dLon := (lon2 - lon1) * rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * r * math.Asin(math.Sqrt(a))
}

// Cache keeps one lookup per outbound, valid while the exit IP is unchanged.
type Cache struct {
	mu      sync.Mutex
	entries map[string]CacheEntry
	TTL     time.Duration
}

// CacheEntry is one cached lookup.
type CacheEntry struct {
	OutboundID string    `json:"outboundId"`
	Info       Info      `json:"info"`
	FetchedAt  time.Time `json:"fetchedAt"`
}

// Get returns the entry for outboundID if it was fetched for exitIP and is
// younger than the TTL (default 24h). exitIP "" skips the IP comparison.
func (c *Cache) Get(outboundID, exitIP string) (*Info, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[outboundID]
	if !ok {
		return nil, false
	}
	ttl := c.TTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	if time.Since(e.FetchedAt) > ttl || (exitIP != "" && exitIP != e.Info.IP) {
		return nil, false
	}
	info := e.Info
	return &info, true
}

// Put stores a lookup.
func (c *Cache) Put(outboundID string, info *Info) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]CacheEntry{}
	}
	c.entries[outboundID] = CacheEntry{OutboundID: outboundID, Info: *info, FetchedAt: time.Now()}
}

// Snapshot / Load let the app persist the cache across restarts.
func (c *Cache) Snapshot() []CacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CacheEntry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	return out
}

func (c *Cache) Load(entries []CacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]CacheEntry{}
	for _, e := range entries {
		c.entries[e.OutboundID] = e
	}
}
