package config

import "fmt"

// XrayOutbounds lists, in stable order, the outbounds of enabled profiles
// that Xray-core must run (and therefore need an internal SOCKS inbound).
func XrayOutbounds(s *State) []*Outbound {
	seen := map[string]bool{}
	var out []*Outbound
	for _, p := range s.Profiles {
		if p.Disabled {
			continue
		}
		members, _ := s.ResolveOutbounds(p)
		for _, o := range members {
			if seen[o.ID] {
				continue
			}
			if eng, err := o.Engine(); err == nil && eng == EngineXray {
				seen[o.ID] = true
				out = append(out, o)
			}
		}
	}
	return out
}

// Built is the pair of core configs for one State.
type Built struct {
	Xray            []byte // nil when no outbound needs Xray
	SingBox         []byte
	ProfileOutbound map[string]string
	Warnings        []string
}

// Build renders both configs. alloc hands out the internal Xray SOCKS
// inbounds (the engine picks free loopback ports and random credentials).
func Build(s *State, alloc func(o *Outbound) (XrayInbound, error)) (*Built, error) {
	xobs := XrayOutbounds(s)
	xin := map[string]XrayInbound{}
	var list []XrayInbound
	var warnings []string
	var usable []*Outbound
	for _, o := range xobs {
		// Validate the Xray rendering up front so a bad outbound degrades to
		// "blocked" for its profile instead of failing the whole start.
		if _, err := XrayOutbound(o, o.ID); err != nil {
			warnings = append(warnings, fmt.Sprintf("outbound %s (%s): %v", o.ID, o.Remark, err))
			continue
		}
		in, err := alloc(o)
		if err != nil {
			return nil, err
		}
		in.OutboundID = o.ID
		xin[o.ID] = in
		list = append(list, in)
		usable = append(usable, o)
	}
	sb, err := BuildSingBox(s, xin)
	if err != nil {
		return nil, err
	}
	b := &Built{SingBox: sb.Config, ProfileOutbound: sb.ProfileOutbound, Warnings: append(warnings, sb.Warnings...)}
	if len(list) > 0 {
		b.Xray, err = BuildXray(usable, list, s.Settings.LogLevel)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}
