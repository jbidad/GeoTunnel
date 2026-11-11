// Package geo looks up the exit location of an outbound (through that
// outbound) and derives time zone, coordinates and language from it.
package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // IANA data on platforms without zoneinfo (Windows, mobile)
)

// Info is the normalised answer of a GeoIP provider.
type Info struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"` // ISO 3166-1 alpha-2, upper case
	CountryName string  `json:"countryName,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Org         string  `json:"org,omitempty"`
	Provider    string  `json:"provider"`
}

// Provider is one GeoIP endpoint.
type Provider struct {
	Name  string
	URL   string
	Parse func(body []byte) (*Info, error)
}

// DefaultProviders are tried in order. All are queried through the profile's
// own outbound, so they see the exit IP, never the user's.
var DefaultProviders = []Provider{
	{Name: "ipinfo.io", URL: "https://ipinfo.io/json", Parse: parseIPInfo},
	{Name: "ipwho.is", URL: "https://ipwho.is/", Parse: parseIPWhois},
	// ip-api.com's free tier is HTTP only; the request still travels inside
	// the tunnel, but the response can be tampered with on the exit side.
	{Name: "ip-api.com", URL: "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,org,query", Parse: parseIPAPI},
}

// Lookup asks each provider in turn and returns the first good answer.
func Lookup(ctx context.Context, client *http.Client, providers []Provider) (*Info, error) {
	if len(providers) == 0 {
		providers = DefaultProviders
	}
	var errs []error
	for _, p := range providers {
		info, err := fetch(ctx, client, p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.Name, err))
			continue
		}
		info.Provider = p.Name
		info.Country = strings.ToUpper(info.Country)
		if info.Timezone != "" {
			if _, err := time.LoadLocation(info.Timezone); err != nil {
				info.Timezone = ""
			}
		}
		if info.Timezone == "" {
			info.Timezone = CountryTimezone(info.Country)
		}
		return info, nil
	}
	return nil, fmt.Errorf("all GeoIP providers failed: %w", errors.Join(errs...))
}

func fetch(ctx context.Context, client *http.Client, p Provider) (*Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GeoTunnel")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	info, err := p.Parse(body)
	if err != nil {
		return nil, err
	}
	if info.IP == "" || info.Country == "" {
		return nil, errors.New("incomplete answer")
	}
	return info, nil
}

func parseIPInfo(b []byte) (*Info, error) {
	var r struct {
		IP, City, Region, Country, Loc, Org, Timezone string
		Bogon                                          bool
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Bogon {
		return nil, errors.New("bogon address")
	}
	info := &Info{IP: r.IP, City: r.City, Region: r.Region, Country: r.Country, Org: r.Org, Timezone: r.Timezone}
	if lat, lon, ok := strings.Cut(r.Loc, ","); ok {
		info.Lat, _ = strconv.ParseFloat(lat, 64)
		info.Lon, _ = strconv.ParseFloat(lon, 64)
	}
	return info, nil
}

func parseIPWhois(b []byte) (*Info, error) {
	var r struct {
		IP          string  `json:"ip"`
		Success     bool    `json:"success"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"country_code"`
		Region      string  `json:"region"`
		City        string  `json:"city"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Connection  struct {
			Org string `json:"org"`
		} `json:"connection"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !r.Success {
		return nil, fmt.Errorf("provider error: %s", r.Message)
	}
	return &Info{IP: r.IP, Country: r.CountryCode, CountryName: r.Country, Region: r.Region, City: r.City,
		Lat: r.Latitude, Lon: r.Longitude, Org: r.Connection.Org, Timezone: r.Timezone.ID}, nil
}

func parseIPAPI(b []byte) (*Info, error) {
	var r struct {
		Status, Message, Country, CountryCode, RegionName, City, Timezone, Org, Query string
		Lat, Lon                                                                      float64
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("provider error: %s", r.Message)
	}
	return &Info{IP: r.Query, Country: r.CountryCode, CountryName: r.Country, Region: r.RegionName, City: r.City,
		Lat: r.Lat, Lon: r.Lon, Org: r.Org, Timezone: r.Timezone}, nil
}

// ExitIP fetches only the exit IP (cheap check used to decide whether a
// cached lookup is still valid).
func ExitIP(ctx context.Context, client *http.Client) (string, error) {
	var errs []error
	for _, u := range []string{"https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"} {
		ip, err := fetchText(ctx, client, u)
		if err == nil && ip != "" {
			return ip, nil
		}
		errs = append(errs, err)
	}
	return "", fmt.Errorf("exit IP check failed: %w", errors.Join(errs...))
}

func fetchText(ctx context.Context, client *http.Client, u string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/8")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return strings.TrimSpace(string(b)), nil
}
