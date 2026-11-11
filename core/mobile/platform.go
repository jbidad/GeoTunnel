package mobile

import (
	"context"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

// Platform is implemented by the host app: the Android VpnService or the iOS
// NEPacketTunnelProvider. gomobile turns it into a Java interface / ObjC
// protocol.
type Platform interface {
	// OpenTun establishes the system tunnel and returns its file descriptor.
	// Android: VpnService.Builder (addAllowedApplication for each
	// IncludePackages entry, otherwise addDisallowedApplication(self)).
	// iOS: setTunnelNetworkSettings, then the utun fd.
	OpenTun(cfg *TunConfig) (int32, error)
	// FindPackage returns the Android package owning a connection
	// (ConnectivityManager.getConnectionOwnerUid + PackageManager), "" if
	// unknown. iOS returns "".
	FindPackage(ipProtocol int32, srcAddr string, srcPort int32, dstAddr string, dstPort int32) (string, error)
	// UnderNetworkExtension is true on iOS.
	UnderNetworkExtension() bool
}

// TunConfig is what the host needs to build the tunnel. List fields are
// newline-separated (gomobile has no slice-of-string support).
type TunConfig struct {
	MTU             int32
	IPv4            string // CIDRs, e.g. 172.19.0.1/30
	IPv6            string
	Routes4         string // routes to capture, e.g. 0.0.0.0/0
	Routes6         string
	IncludePackages string // Android per-app VPN
	ExcludePackages string
	DNSServer       string // address the host should announce as DNS
}

// platformAdapter implements sing-box's adapter.PlatformInterface on top of
// the small Platform interface. GeoTunnel never needs socket protection: on
// Android its own package is always outside the VPN (allowed list, or
// addDisallowedApplication(self) for whole-device), and on iOS the extension's
// sockets bypass its own tunnel.
type platformAdapter struct {
	p          Platform
	mu         sync.Mutex
	myTunAddrs []netip.Addr
	monitor    *interfaceMonitor
}

var _ adapter.PlatformInterface = (*platformAdapter)(nil)

func newPlatformAdapter(p Platform) *platformAdapter {
	return &platformAdapter{p: p, monitor: sharedMonitor}
}

func (w *platformAdapter) Initialize(adapter.NetworkManager) error     { return nil }
func (w *platformAdapter) UsePlatformAutoDetectInterfaceControl() bool { return false }
func (w *platformAdapter) AutoDetectInterfaceControl(int) error        { return nil }
func (w *platformAdapter) UsePlatformInterface() bool                  { return true }

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, "\n")
}

func (w *platformAdapter) OpenInterface(options *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	ranges, err := options.BuildAutoRouteRanges(w.p.UnderNetworkExtension())
	if err != nil {
		return nil, err
	}
	var r4, r6 []netip.Prefix
	for _, r := range ranges {
		if r.Addr().Is4() {
			r4 = append(r4, r)
		} else {
			r6 = append(r6, r)
		}
	}
	cfg := &TunConfig{
		MTU:             int32(options.MTU),
		IPv4:            joinPrefixes(options.Inet4Address),
		IPv6:            joinPrefixes(options.Inet6Address),
		Routes4:         joinPrefixes(r4),
		Routes6:         joinPrefixes(r6),
		IncludePackages: strings.Join(options.IncludePackage, "\n"),
		ExcludePackages: strings.Join(options.ExcludePackage, "\n"),
	}
	if len(options.Inet4Address) > 0 {
		// sing-box answers DNS on the next address of the TUN subnet.
		cfg.DNSServer = options.Inet4Address[0].Addr().Next().String()
	}
	fd, err := w.p.OpenTun(cfg)
	if err != nil {
		return nil, E.Cause(err, "open tun")
	}
	name, err := tunnelName(fd)
	if err != nil {
		return nil, E.Cause(err, "query tun name")
	}
	options.Name = name
	if options.InterfaceMonitor != nil {
		options.InterfaceMonitor.RegisterMyInterface(name)
	}
	nfd, err := dupFd(int(fd))
	if err != nil {
		return nil, E.Cause(err, "dup tun fd")
	}
	options.FileDescriptor = nfd
	w.mu.Lock()
	w.myTunAddrs = nil
	for _, p := range append(append([]netip.Prefix{}, options.Inet4Address...), options.Inet6Address...) {
		w.myTunAddrs = append(w.myTunAddrs, p.Addr())
	}
	w.mu.Unlock()
	return tun.New(*options)
}

func (w *platformAdapter) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }
func (w *platformAdapter) UsePlatformDefaultInterfaceMonitor() bool               { return true }
func (w *platformAdapter) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return w.monitor
}
func (w *platformAdapter) UsePlatformNetworkInterfaces() bool { return true }

func (w *platformAdapter) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	iface := w.monitor.DefaultInterface()
	if iface == nil {
		return nil, nil
	}
	return []adapter.NetworkInterface{{Interface: *iface, Expensive: w.monitor.expensive, Constrained: w.monitor.constrained}}, nil
}

func (w *platformAdapter) UnderNetworkExtension() bool              { return w.p.UnderNetworkExtension() }
func (w *platformAdapter) NetworkExtensionIncludeAllNetworks() bool { return false }
func (w *platformAdapter) ClearDNSCache()                           {}
func (w *platformAdapter) RequestPermissionForWIFIState() error     { return nil }
func (w *platformAdapter) ReadWIFIState(context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}
func (w *platformAdapter) UsePlatformConnectionOwnerFinder() bool { return true }

func (w *platformAdapter) FindConnectionOwner(r *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	pkg, err := w.p.FindPackage(r.IpProtocol, r.SourceAddress, r.SourcePort, r.DestinationAddress, r.DestinationPort)
	if err != nil {
		return nil, err
	}
	if pkg == "" {
		return nil, E.New("connection owner not found")
	}
	return &adapter.ConnectionOwner{AndroidPackageNames: []string{pkg}}, nil
}

func (w *platformAdapter) UsePlatformWIFIMonitor() bool                 { return false }
func (w *platformAdapter) UsePlatformNotification() bool                { return false }
func (w *platformAdapter) SendNotification(*adapter.Notification) error { return nil }
func (w *platformAdapter) CancelNotification(string, int32) error       { return nil }
func (w *platformAdapter) MyInterfaceAddress() []netip.Addr {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.myTunAddrs
}
func (w *platformAdapter) UsePlatformNeighborResolver() bool                         { return false }
func (w *platformAdapter) StartNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (w *platformAdapter) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (w *platformAdapter) UsePlatformShell() bool                                    { return false }
func (w *platformAdapter) CheckPlatformShell() error                                 { return E.New("unsupported") }
func (w *platformAdapter) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, E.New("unsupported")
}
func (w *platformAdapter) LookupUser(string) (*adapter.PlatformUser, error) {
	return nil, E.New("unsupported")
}
func (w *platformAdapter) LookupSFTPServer() (string, error)     { return "", E.New("unsupported") }
func (w *platformAdapter) ReadSystemSSHHostKey() ([]byte, error) { return nil, E.New("unsupported") }
func (w *platformAdapter) TailscaleHostname() string             { return "" }
func (w *platformAdapter) UsePlatformBridge() bool               { return false }
func (w *platformAdapter) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, E.New("unsupported")
}

// interfaceMonitor is fed by the host's network callback
// (UpdateDefaultInterface) instead of netlink, which Android apps may not
// use.
type interfaceMonitor struct {
	mu          sync.Mutex
	iface       *control.Interface
	expensive   bool
	constrained bool
	callbacks   list.List[tun.DefaultInterfaceUpdateCallback]
	mine        []string
}

var sharedMonitor = &interfaceMonitor{}

func (m *interfaceMonitor) Start() error { return nil }
func (m *interfaceMonitor) Close() error { return nil }
func (m *interfaceMonitor) DefaultInterface() *control.Interface {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.iface
}
func (m *interfaceMonitor) OverrideAndroidVPN() bool { return false }
func (m *interfaceMonitor) AndroidVPNEnabled() bool  { return false }
func (m *interfaceMonitor) RegisterCallback(cb tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(cb)
}
func (m *interfaceMonitor) UnregisterCallback(e *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(e)
}
func (m *interfaceMonitor) RegisterMyInterface(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mine = append(m.mine, name)
}
func (m *interfaceMonitor) MyInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.mine...)
}

func (m *interfaceMonitor) update(iface *control.Interface, expensive, constrained bool) {
	m.mu.Lock()
	m.iface, m.expensive, m.constrained = iface, expensive, constrained
	var cbs []tun.DefaultInterfaceUpdateCallback
	for e := m.callbacks.Front(); e != nil; e = e.Next() {
		cbs = append(cbs, e.Value)
	}
	m.mu.Unlock()
	for _, cb := range cbs {
		cb(iface, 0)
	}
}
