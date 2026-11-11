package webapp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/coder/websocket"
)

// transport carries raw CDP messages.
type transport interface {
	Send([]byte) error
	Recv() ([]byte, error)
	Close() error
}

// pipeTransport speaks Chrome's --remote-debugging-pipe framing: JSON
// messages terminated by NUL on fds 3 (to Chrome) and 4 (from Chrome).
type pipeTransport struct {
	w  *os.File
	r  *bufio.Reader
	rc io.Closer
	mu sync.Mutex
}

func (p *pipeTransport) Send(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.w.Write(append(b, 0))
	return err
}

func (p *pipeTransport) Recv() ([]byte, error) {
	b, err := p.r.ReadBytes(0)
	if err != nil {
		return nil, err
	}
	return b[:len(b)-1], nil
}

func (p *pipeTransport) Close() error {
	p.w.Close()
	return p.rc.Close()
}

// wsTransport is used where pipes can't be inherited (Windows): Chrome
// listens on a random loopback port written to DevToolsActivePort.
type wsTransport struct{ c *websocket.Conn }

func (w *wsTransport) Send(b []byte) error {
	return w.c.Write(context.Background(), websocket.MessageText, b)
}

func (w *wsTransport) Recv() ([]byte, error) {
	_, b, err := w.c.Read(context.Background())
	return b, err
}

func (w *wsTransport) Close() error { return w.c.Close(websocket.StatusNormalClosure, "") }

// Conn is a minimal flattened-session CDP client.
type Conn struct {
	t       transport
	nextID  atomic.Int64
	mu      sync.Mutex
	pending map[int64]chan cdpMsg
	onEvent func(sessionID, method string, params json.RawMessage)
	closed  chan struct{}
	err     error
}

type cdpMsg struct {
	ID        int64           `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func newConn(t transport, onEvent func(sessionID, method string, params json.RawMessage)) *Conn {
	c := &Conn{t: t, pending: map[int64]chan cdpMsg{}, onEvent: onEvent, closed: make(chan struct{})}
	go c.readLoop()
	return c
}

func (c *Conn) readLoop() {
	defer close(c.closed)
	for {
		b, err := c.t.Recv()
		if err != nil {
			c.mu.Lock()
			c.err = err
			for id, ch := range c.pending {
				close(ch)
				delete(c.pending, id)
			}
			c.mu.Unlock()
			return
		}
		var m cdpMsg
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Method != "" && c.onEvent != nil {
			c.onEvent(m.SessionID, m.Method, m.Params)
		}
	}
}

// Call sends a command (sessionID "" = browser target) and waits.
func (c *Conn) Call(ctx context.Context, sessionID, method string, params any) (json.RawMessage, error) {
	id := c.nextID.Add(1)
	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if sessionID != "" {
		msg["sessionId"] = sessionID
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	ch := make(chan cdpMsg, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	c.pending[id] = ch
	c.mu.Unlock()
	if err := c.t.Send(b); err != nil {
		return nil, err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return nil, errors.New("cdp: connection closed")
		}
		if m.Error != nil {
			return nil, fmt.Errorf("cdp %s: %s", method, m.Error.Message)
		}
		return m.Result, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Closed is closed when the browser goes away.
func (c *Conn) Closed() <-chan struct{} { return c.closed }
