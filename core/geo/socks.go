package geo

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// SOCKS5Dialer dials through a SOCKS5 proxy and always sends the hostname to
// the proxy (remote DNS, "socks5h" semantics) so lookups never resolve on the
// local network.
type SOCKS5Dialer struct {
	ProxyAddr  string // host:port
	User, Pass string
	Timeout    time.Duration
}

// DialContext implements the http.Transport dial hook.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("socks5: network %s not supported", network)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	nd := net.Dialer{Timeout: timeout}
	conn, err := nd.DialContext(ctx, "tcp", d.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("socks5: connect proxy: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := d.handshake(conn, host, port); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *SOCKS5Dialer) handshake(conn net.Conn, host string, port int) error {
	methods := []byte{0x00}
	if d.User != "" {
		methods = []byte{0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5: greeting: %w", err)
	}
	if resp[0] != 0x05 {
		return errors.New("socks5: bad version")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		req := []byte{0x01, byte(len(d.User))}
		req = append(req, d.User...)
		req = append(req, byte(len(d.Pass)))
		req = append(req, d.Pass...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, resp); err != nil {
			return err
		}
		if resp[1] != 0x00 {
			return errors.New("socks5: authentication failed")
		}
	default:
		return errors.New("socks5: no acceptable auth method")
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5: reply: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5: connect failed (code %d)", head[1])
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("socks5: bad address type in reply")
	}
	_, err := io.ReadFull(conn, make([]byte, skip+2))
	return err
}

// HTTPClient returns an http.Client whose every connection goes through the
// proxy. Proxy env vars are ignored on purpose.
func (d *SOCKS5Dialer) HTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
