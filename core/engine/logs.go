package engine

import (
	"strings"
	"sync"
	"time"

	"geotunnel/core/config"
)

// LogLine is one scrubbed log entry.
type LogLine struct {
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Source string    `json:"source"` // engine | xray | singbox
	Msg    string    `json:"msg"`
}

// LogHub keeps the last lines in a ring buffer and fans them out. Every
// line passes the Scrubber first, so credentials never reach the UI, files
// or exports.
type LogHub struct {
	mu    sync.Mutex
	ring  []LogLine
	next  int
	full  bool
	subs  map[int]chan LogLine
	subID int
	Scrub *config.Scrubber
}

func NewLogHub(size int, scrub *config.Scrubber) *LogHub {
	return &LogHub{ring: make([]LogLine, size), subs: map[int]chan LogLine{}, Scrub: scrub}
}

func (h *LogHub) Write(source, level, msg string) {
	msg = strings.TrimRight(msg, "\r\n")
	if h.Scrub != nil {
		msg = h.Scrub.Scrub(msg)
	}
	line := LogLine{Time: time.Now(), Level: level, Source: source, Msg: msg}
	h.mu.Lock()
	h.ring[h.next] = line
	h.next = (h.next + 1) % len(h.ring)
	if h.next == 0 {
		h.full = true
	}
	for _, ch := range h.subs {
		select {
		case ch <- line:
		default: // slow subscriber: drop rather than block the cores
		}
	}
	h.mu.Unlock()
}

// Recent returns buffered lines, oldest first.
func (h *LogHub) Recent() []LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.full {
		return append([]LogLine(nil), h.ring[:h.next]...)
	}
	return append(append([]LogLine(nil), h.ring[h.next:]...), h.ring[:h.next]...)
}

// Subscribe streams new lines until cancel is called.
func (h *LogHub) Subscribe() (<-chan LogLine, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.subID++
	id := h.subID
	ch := make(chan LogLine, 256)
	h.subs[id] = ch
	return ch, func() {
		h.mu.Lock()
		if c, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(c)
		}
		h.mu.Unlock()
	}
}
