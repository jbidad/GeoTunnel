// Command core is GeoTunnel's desktop sidecar.
//
//	core serve   --socket PATH | --pipe NAME | --tcp ADDR   run the engine behind authenticated IPC
//	core bridge  --socket PATH | --pipe NAME                stdio <-> IPC (for clients without pipe support)
//	core run     STATE.json                                 run the engine in the foreground (dev / tests)
//	core check   STATE.json                                 build and validate both core configs
//	core build   STATE.json                                 print the generated configs (redacted)
//	core import  [FILE|-]                                   parse links / subscription / JSON into outbounds
//	core webapp  --url URL --proxy-port N --tz ZONE ...     open a web app in an isolated Chromium (CDP)
//	core launch  --tz ZONE --lang TAG -- APP [ARGS...]      start a native app with TZ/LANG set
//	core apps                                               list installed desktop apps (JSON)
//	core version
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"geotunnel/core/config"
	"geotunnel/core/desktop"
	"geotunnel/core/engine"
	"geotunnel/core/ipc"
	"geotunnel/core/webapp"
)

var version = "dev"

func main() {
	ipc.Version = version
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "bridge":
		err = cmdBridge(args)
	case "run":
		err = cmdRun(args)
	case "check":
		err = cmdCheck(args, false)
	case "build":
		err = cmdCheck(args, true)
	case "import":
		err = cmdImport(args)
	case "webapp":
		err = cmdWebApp(args)
	case "launch":
		err = cmdLaunch(args)
	case "apps":
		err = cmdApps()
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "core:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: core serve|bridge|run|check|build|import|webapp|launch|apps|version [flags]")
	os.Exit(2)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// --- serve -----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	sock := fs.String("socket", "", "unix socket path (macOS/Linux)")
	pipe := fs.String("pipe", "", `named pipe (Windows), e.g. \\.\pipe\geotunnel-core`)
	tcp := fs.String("tcp", "", "loopback TCP address (development only)")
	tokenFile := fs.String("token-file", "", "write a fresh token here (0600, owned by --owner-uid); default: $GEOTUNNEL_TOKEN")
	ownerUID := fs.Int("owner-uid", -1, "uid allowed to connect (privileged helper on macOS/Linux)")
	allowSID := fs.String("allow-sid", "", "user SID allowed to connect (privileged service on Windows)")
	privileged := fs.Bool("privileged", false, "running as the TUN helper: refuse to launch browsers/apps")
	fs.Parse(args)

	token := os.Getenv("GEOTUNNEL_TOKEN")
	if *tokenFile != "" {
		token = randomToken()
		if err := writeToken(*tokenFile, token, *ownerUID); err != nil {
			return err
		}
	}
	if token == "" {
		return errors.New("no token: set GEOTUNNEL_TOKEN or pass --token-file")
	}
	var (
		l   net.Listener
		err error
	)
	switch {
	case *sock != "":
		l, err = listenUnix(*sock, *ownerUID)
	case *pipe != "":
		l, err = listenPipe(*pipe, *allowSID)
	case *tcp != "":
		if host, _, _ := net.SplitHostPort(*tcp); host != "127.0.0.1" && host != "::1" && host != "localhost" {
			return errors.New("--tcp must be a loopback address")
		}
		l, err = net.Listen("tcp", *tcp)
	default:
		return errors.New("one of --socket, --pipe or --tcp is required")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "core: listening on %s\n", l.Addr())
	e := engine.New(engine.Options{})
	srv := &ipc.Server{Engine: e, Token: token, AllowWebApps: !*privileged}
	return runService(func(ctx context.Context) error {
		go func() {
			<-ctx.Done()
			l.Close()
		}()
		err := srv.Serve(l)
		e.Stop()
		return err
	})
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// --- bridge ----------------------------------------------------------------

func cmdBridge(args []string) error {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	sock := fs.String("socket", "", "unix socket path")
	pipe := fs.String("pipe", "", "named pipe")
	fs.Parse(args)
	var (
		c   net.Conn
		err error
	)
	switch {
	case *sock != "":
		c, err = net.Dial("unix", *sock)
	case *pipe != "":
		c, err = dialPipe(*pipe)
	default:
		return errors.New("--socket or --pipe required")
	}
	if err != nil {
		return err
	}
	defer c.Close()
	done := make(chan struct{}, 2)
	go func() { io.Copy(c, os.Stdin); done <- struct{}{} }()
	go func() { io.Copy(os.Stdout, c); done <- struct{}{} }()
	<-done
	return nil
}

// --- run / check / build / import ----------------------------------------------

func readArg(args []string) ([]byte, error) {
	if len(args) == 0 || args[0] == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(args[0])
}

func cmdRun(args []string) error {
	b, err := readArg(args)
	if err != nil {
		return err
	}
	e := engine.New(engine.Options{})
	if err := e.Start(b); err != nil {
		return err
	}
	ch, stop := e.Logs.Subscribe()
	defer stop()
	for _, l := range e.Logs.Recent() {
		fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", l.Time.Format("15:04:05"), l.Level, l.Source, l.Msg)
	}
	st := e.Stats()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "started", "profileOutbound": st.ProfileOutbound})
	ctx, cancel := signalContext()
	defer cancel()
	for {
		select {
		case l := <-ch:
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", l.Time.Format("15:04:05"), l.Level, l.Source, l.Msg)
		case <-ctx.Done():
			return e.Stop()
		}
	}
}

func cmdCheck(args []string, print bool) error {
	b, err := readArg(args)
	if err != nil {
		return err
	}
	st, err := config.ParseState(b)
	if err != nil {
		return err
	}
	built, err := config.Build(st, func(*config.Outbound) (config.XrayInbound, error) {
		return config.XrayInbound{Port: 1, User: "u", Pass: "p"}, nil
	})
	if err != nil {
		return err
	}
	for _, w := range built.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if built.Xray != nil {
		if err := engine.CheckXray(built.Xray); err != nil {
			return fmt.Errorf("xray: %w", err)
		}
	}
	if err := engine.CheckSingBox(built.SingBox); err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	if print {
		out := map[string]json.RawMessage{"singbox": config.RedactJSONConfig(built.SingBox)}
		if built.Xray != nil {
			out["xray"] = config.RedactJSONConfig(built.Xray)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	fmt.Println("ok")
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	group := fs.String("group", "", "subscription id to stamp on the outbounds")
	fs.Parse(args)
	b, err := readArg(fs.Args())
	if err != nil {
		return err
	}
	res, err := config.ParseImport(b, *group)
	if res != nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)
	}
	return err
}

// --- webapp / launch / apps ----------------------------------------------------

func cmdWebApp(args []string) error {
	fs := flag.NewFlagSet("webapp", flag.ExitOnError)
	var o webapp.Options
	fs.StringVar(&o.URL, "url", "", "web app URL")
	fs.IntVar(&o.ProxyPort, "proxy-port", 0, "profile SOCKS5 port on 127.0.0.1")
	fs.StringVar(&o.Timezone, "tz", "", "IANA time zone")
	fs.StringVar(&o.Locale, "lang", "", "BCP 47 language, e.g. tr-TR")
	fs.Float64Var(&o.Lat, "lat", 0, "latitude")
	fs.Float64Var(&o.Lon, "lon", 0, "longitude")
	fs.Float64Var(&o.AccuracyM, "accuracy", 3000, "accuracy in metres")
	fs.StringVar(&o.UserDataDir, "user-data-dir", "", "isolated browser profile directory")
	fs.StringVar(&o.Browser, "browser", "", "Chromium-family executable (default: detect)")
	fs.BoolVar(&o.Headless, "headless", false, "run headless (leak tests)")
	fs.StringVar(&o.WebRTC, "webrtc", "disable", "disable | proxy-only")
	probe := fs.Bool("probe", false, "after load, run the read-only leak probe and print {type:probe}")
	echoURL := fs.String("echo-url", "", "header echo endpoint for the probe")
	fs.Parse(args)
	ctx, cancel := signalContext()
	defer cancel()
	enc := json.NewEncoder(os.Stdout)
	o.OnEvent = func(ev webapp.Event) { enc.Encode(ev) }
	s, err := webapp.Launch(ctx, o)
	if err != nil {
		return err
	}
	enc.Encode(webapp.Event{Type: "ready"})
	if *probe {
		pctx, pcancel := context.WithTimeout(ctx, 60*time.Second)
		defer pcancel()
		if err := s.WaitLoad(pctx); err != nil {
			return err
		}
		res, err := s.Evaluate(pctx, webapp.LeakProbe(*echoURL))
		if err != nil {
			return err
		}
		enc.Encode(map[string]any{"type": "probe", "result": res})
		if o.Headless {
			return s.Close()
		}
	}
	select {
	case <-ctx.Done():
		return s.Close()
	case <-s.Done():
		return nil
	}
}

func cmdLaunch(args []string) error {
	fs := flag.NewFlagSet("launch", flag.ExitOnError)
	tz := fs.String("tz", "", "IANA time zone for TZ")
	lang := fs.String("lang", "", "locale, e.g. tr-TR (sets LANG/LC_ALL)")
	proxy := fs.Int("proxy-port", 0, "also export ALL_PROXY/HTTP(S)_PROXY to this profile port")
	fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return errors.New("usage: core launch --tz ZONE --lang TAG -- APP [ARGS...]")
	}
	pid, err := desktop.Launch(desktop.LaunchOptions{Path: rest[0], Args: rest[1:], Timezone: *tz, Locale: *lang, ProxyPort: *proxy})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"pid": pid})
}

func cmdApps() error {
	apps, err := desktop.ListApps()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(apps)
}

func writeToken(path, token string, uid int) error {
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return err
	}
	if uid >= 0 {
		return chownPath(path, uid)
	}
	return nil
}
