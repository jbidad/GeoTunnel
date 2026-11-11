// Package ipc is the authenticated JSON-RPC channel between the
// unprivileged UI and the core (possibly running as a privileged helper).
//
// Framing: one JSON object per line. The first request on a connection must
// be {"method":"auth","params":{"token":"..."}}; anything else closes it.
// Server-initiated notifications (log lines) have no "id".
package ipc

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"geotunnel/core/config"
	"geotunnel/core/engine"
	"geotunnel/core/geo"
)

// Version is reported by the "version" method.
var Version = "dev"

type request struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"` // notifications
	Result any             `json:"result,omitempty"`
	Params any             `json:"params,omitempty"` // notifications
	Error  *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server dispatches requests to an engine.
type Server struct {
	Engine *engine.Engine
	Token  string
	// AllowWebApps permits methods that start user programs; the privileged
	// helper sets this false so a browser never runs as root.
	AllowWebApps bool

	mu    sync.Mutex
	state []byte // last state passed to start/reload
}

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	if s.Token == "" {
		return errors.New("ipc: refusing to serve without a token")
	}
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), 32<<20)
	var wmu sync.Mutex
	write := func(r response) {
		b, _ := json.Marshal(r)
		wmu.Lock()
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		c.Write(append(b, '\n'))
		wmu.Unlock()
	}

	// Authenticate.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if !sc.Scan() {
		return
	}
	var first request
	if json.Unmarshal(sc.Bytes(), &first) != nil || first.Method != "auth" {
		write(response{Error: &rpcError{401, "auth required"}})
		return
	}
	var ap struct{ Token string }
	if json.Unmarshal(first.Params, &ap) != nil {
		ap.Token = ""
	}
	if subtle.ConstantTimeCompare([]byte(ap.Token), []byte(s.Token)) != 1 {
		time.Sleep(500 * time.Millisecond)
		write(response{ID: first.ID, Error: &rpcError{401, "bad token"}})
		return
	}
	write(response{ID: first.ID, Result: map[string]any{"ok": true, "version": Version}})
	c.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Answer everything already received even if the client half-closes.
	var inflight sync.WaitGroup
	defer inflight.Wait()
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			write(response{Error: &rpcError{400, "bad json"}})
			continue
		}
		if req.Method == "logs.subscribe" {
			ch, stop := s.Engine.Logs.Subscribe()
			go func() {
				<-ctx.Done()
				stop()
			}()
			go func() {
				for line := range ch {
					write(response{Method: "log", Params: line})
				}
			}()
			write(response{ID: req.ID, Result: map[string]any{"ok": true}})
			continue
		}
		inflight.Add(1)
		go func(req request) {
			defer inflight.Done()
			res, err := s.dispatch(ctx, req.Method, req.Params)
			if err != nil {
				write(response{ID: req.ID, Error: &rpcError{500, err.Error()}})
				return
			}
			write(response{ID: req.ID, Result: res})
		}(req)
	}
}

func (s *Server) lastState() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (any, error) {
	e := s.Engine
	switch method {
	case "version":
		return map[string]string{"version": Version}, nil
	case "start", "reload":
		var p struct {
			State json.RawMessage `json:"state"`
		}
		if err := json.Unmarshal(params, &p); err != nil || len(p.State) == 0 {
			return nil, errors.New("params.state required")
		}
		var err error
		if method == "start" {
			err = e.Start(p.State)
		} else if e.Running() {
			err = e.Reload(p.State)
		} else {
			err = e.Start(p.State)
		}
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.state = p.State
		s.mu.Unlock()
		return e.Stats(), nil
	case "stop":
		return map[string]bool{"ok": true}, e.Stop()
	case "stats":
		return e.Stats(), nil
	case "testOutbound":
		var p struct {
			ID    string          `json:"id"`
			State json.RawMessage `json:"state"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		st := p.State
		if len(st) == 0 {
			st = s.lastState()
		}
		if len(st) == 0 {
			return nil, errors.New("no state: pass params.state or start first")
		}
		return e.TestOutbound(ctx, st, p.ID), nil
	case "geoLookup":
		var p struct {
			ProfileID string `json:"profileId"`
			Force     bool   `json:"force"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return e.GeoLookup(ctx, p.ProfileID, p.Force)
	case "leakTest":
		var p struct {
			ProfileID     string `json:"profileId"`
			CompareDirect bool   `json:"compareDirect"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		rep, real, err := e.LeakTestNetwork(ctx, p.ProfileID, engine.LeakOptions{CompareDirect: p.CompareDirect})
		if err != nil {
			return nil, err
		}
		rep.Finish()
		return map[string]any{"report": rep, "real": real}, nil
	case "evaluateBrowser":
		var p struct {
			Expected geo.Derived            `json:"expected"`
			Observed engine.BrowserObserved `json:"observed"`
			Real     *engine.RealIPs        `json:"real"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		return engine.EvaluateBrowser(p.Expected, p.Observed, p.Real), nil
	case "logs.recent":
		return e.Logs.Recent(), nil
	case "built":
		x, sb, err := e.Built()
		if err != nil {
			return nil, err
		}
		return map[string]json.RawMessage{"xray": nullIfEmpty(x), "singbox": nullIfEmpty(sb)}, nil
	case "parseImport":
		var p struct {
			Text  string `json:"text"`
			Group string `json:"group"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		return config.ParseImport([]byte(p.Text), p.Group)
	case "toLink":
		var p struct {
			Outbound config.Outbound `json:"outbound"`
			Redact   bool            `json:"redact"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
		l, err := config.ToLink(&p.Outbound, p.Redact)
		return map[string]string{"link": l}, err
	case "validateState":
		_, err := config.ParseState(params)
		return map[string]bool{"ok": err == nil}, err
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

// decodeParams accepts absent params (methods with only optional fields)
// but rejects malformed ones instead of running with zero values.
func decodeParams(params json.RawMessage, v any) error {
	if len(params) == 0 || string(params) == "null" {
		return nil
	}
	if err := json.Unmarshal(params, v); err != nil {
		return fmt.Errorf("bad params: %w", err)
	}
	return nil
}

func nullIfEmpty(b []byte) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage("null")
	}
	return b
}
