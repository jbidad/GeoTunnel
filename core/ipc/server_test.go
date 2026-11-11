package ipc

import (
	"bufio"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"geotunnel/core/engine"
)

func dial(t *testing.T, path string) (net.Conn, *bufio.Scanner) {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	return c, sc
}

func call(t *testing.T, c net.Conn, sc *bufio.Scanner, line string) map[string]any {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	for sc.Scan() {
		var m map[string]any
		json.Unmarshal(sc.Bytes(), &m)
		if m["method"] == "log" {
			continue
		}
		return m
	}
	return nil
}

func TestAuthAndDispatch(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "core.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s := &Server{Engine: engine.New(engine.Options{}), Token: "secret-token"}
	go s.Serve(l)

	// Wrong token is rejected and the connection closed.
	c, sc := dial(t, sock)
	r := call(t, c, sc, `{"id":1,"method":"auth","params":{"token":"nope"}}`)
	if r["error"] == nil {
		t.Fatal("bad token accepted")
	}
	// No auth first: rejected.
	c, sc = dial(t, sock)
	if r := call(t, c, sc, `{"id":1,"method":"stats"}`); r["error"] == nil {
		t.Fatal("unauthenticated call accepted")
	}

	c, sc = dial(t, sock)
	if r := call(t, c, sc, `{"id":1,"method":"auth","params":{"token":"secret-token"}}`); r["error"] != nil {
		t.Fatalf("auth: %v", r)
	}
	r = call(t, c, sc, `{"id":2,"method":"parseImport","params":{"text":"trojan://pw@198.51.100.7:443#t"}}`)
	res, _ := r["result"].(map[string]any)
	obs, _ := res["outbounds"].([]any)
	if len(obs) != 1 {
		t.Fatalf("parseImport: %v", r)
	}
	r = call(t, c, sc, `{"id":3,"method":"stats"}`)
	if r["error"] != nil {
		t.Fatal(r)
	}
	r = call(t, c, sc, `{"id":4,"method":"nope"}`)
	if e, _ := r["error"].(map[string]any); e == nil || !strings.Contains(e["message"].(string), "unknown method") {
		t.Fatal(r)
	}
}
