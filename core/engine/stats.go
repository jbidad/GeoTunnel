package engine

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Counter holds traffic totals for one outbound tag.
type Counter struct {
	Up, Down, Conns atomic.Int64
}

// tracker counts bytes per outbound tag. It is attached to sing-box's
// router, so it sees TUN and mixed-inbound traffic alike.
type tracker struct {
	mu     sync.Mutex
	counts map[string]*Counter
}

func newTracker() *tracker { return &tracker{counts: map[string]*Counter{}} }

func (t *tracker) counter(tag string) *Counter {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.counts[tag]
	if c == nil {
		c = &Counter{}
		t.counts[tag] = c
	}
	return c
}

func tagOf(o adapter.Outbound) string {
	if o == nil {
		return "reject"
	}
	return o.Tag()
}

func (t *tracker) RoutedConnection(ctx context.Context, conn net.Conn, md adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) net.Conn {
	c := t.counter(tagOf(out))
	c.Conns.Add(1)
	return bufio.NewInt64CounterConn(conn, []*atomic.Int64{&c.Down}, []*atomic.Int64{&c.Up})
}

func (t *tracker) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, md adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) N.PacketConn {
	c := t.counter(tagOf(out))
	c.Conns.Add(1)
	return bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{&c.Down}, nil, []*atomic.Int64{&c.Up}, nil)
}

func (t *tracker) RoutedFlow(ctx context.Context, md adapter.InboundContext, rule adapter.Rule, out adapter.Outbound) tun.FlowTracker {
	return nil
}

// TrafficStat is the exported per-outbound view.
type TrafficStat struct {
	Tag   string `json:"tag"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Conns int64  `json:"conns"`
}

func (t *tracker) snapshot() []TrafficStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TrafficStat, 0, len(t.counts))
	for tag, c := range t.counts {
		out = append(out, TrafficStat{Tag: tag, Up: c.Up.Load(), Down: c.Down.Load(), Conns: c.Conns.Load()})
	}
	return out
}
