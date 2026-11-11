package engine

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sbjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	applog "github.com/xtls/xray-core/app/log"
	commlog "github.com/xtls/xray-core/common/log"
	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Xray-core logs through a process-global handler. Route its console log
// type into whichever hub is current.
var (
	xrayHubMu sync.RWMutex
	xrayHub   *LogHub
)

func init() {
	_ = applog.RegisterHandlerCreator(applog.LogType_Console, func(applog.LogType, applog.HandlerCreatorOptions) (commlog.Handler, error) {
		return commlog.NewLogger(func() commlog.Writer { return xrayWriter{} }), nil
	})
}

type xrayWriter struct{}

func (xrayWriter) Write(s string) error {
	xrayHubMu.RLock()
	h := xrayHub
	xrayHubMu.RUnlock()
	if h != nil {
		level := "info"
		switch {
		case strings.Contains(s, "[Error]"):
			level = "error"
		case strings.Contains(s, "[Warning]"):
			level = "warn"
		case strings.Contains(s, "[Debug]"):
			level = "debug"
		}
		h.Write("xray", level, s)
	}
	return nil
}
func (xrayWriter) Close() error { return nil }

func setXrayHub(h *LogHub) {
	xrayHubMu.Lock()
	xrayHub = h
	xrayHubMu.Unlock()
}

// startXray loads an Xray JSON config and starts the instance.
func startXray(cfg []byte) (*xcore.Instance, error) {
	pb, err := serial.LoadJSONConfig(bytes.NewReader(cfg))
	if err != nil {
		return nil, fmt.Errorf("xray config: %w", err)
	}
	inst, err := xcore.New(pb)
	if err != nil {
		return nil, fmt.Errorf("xray init: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return nil, fmt.Errorf("xray start: %w", err)
	}
	return inst, nil
}

// CheckXray validates an Xray config without starting it.
func CheckXray(cfg []byte) error {
	pb, err := serial.LoadJSONConfig(bytes.NewReader(cfg))
	if err != nil {
		return err
	}
	inst, err := xcore.New(pb)
	if err != nil {
		return err
	}
	return inst.Close()
}

// sing-box -------------------------------------------------------------------

type sbLogWriter struct{ hub *LogHub }

func (w sbLogWriter) WriteMessage(level sblog.Level, message string) {
	if w.hub != nil {
		w.hub.Write("singbox", sblog.FormatLevel(level), message)
	}
}

func singBoxContext(platform adapter.PlatformInterface) context.Context {
	ctx := box.Context(context.Background(), include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(),
		include.CertificateProviderRegistry())
	if platform != nil {
		ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	}
	return ctx
}

func parseSingBox(ctx context.Context, cfg []byte) (option.Options, error) {
	opts, err := sbjson.UnmarshalExtendedContext[option.Options](ctx, cfg)
	if err != nil {
		return option.Options{}, fmt.Errorf("sing-box config: %w", err)
	}
	return opts, nil
}

type singBox struct {
	box    *box.Box
	cancel context.CancelFunc
}

func startSingBox(cfg []byte, platform adapter.PlatformInterface, hub *LogHub, trackers ...adapter.ConnectionTracker) (*singBox, error) {
	ctx, cancel := context.WithCancel(singBoxContext(platform))
	opts, err := parseSingBox(ctx, cfg)
	if err != nil {
		cancel()
		return nil, err
	}
	var lw sblog.PlatformWriter
	if hub != nil {
		lw = sbLogWriter{hub}
		// Our writer receives every line; keep sing-box off stdout.
		if opts.Log == nil {
			opts.Log = &option.LogOptions{}
		}
		opts.Log.Output = ""
		opts.Log.Disabled = false
	}
	inst, err := box.New(box.Options{Options: opts, Context: ctx, PlatformLogWriter: lw})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sing-box init: %w", err)
	}
	for _, t := range trackers {
		inst.Router().AppendTracker(t)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		cancel()
		return nil, fmt.Errorf("sing-box start: %w", err)
	}
	return &singBox{box: inst, cancel: cancel}, nil
}

func (s *singBox) Close() error {
	if s == nil {
		return nil
	}
	err := s.box.Close()
	s.cancel()
	return err
}

// CheckSingBox validates a sing-box config by constructing (not starting)
// the instance, which is what `sing-box check` does.
func CheckSingBox(cfg []byte) error {
	ctx, cancel := context.WithCancel(singBoxContext(nil))
	defer cancel()
	opts, err := parseSingBox(ctx, cfg)
	if err != nil {
		return err
	}
	inst, err := box.New(box.Options{Options: opts, Context: ctx})
	if err != nil {
		return err
	}
	return inst.Close()
}
