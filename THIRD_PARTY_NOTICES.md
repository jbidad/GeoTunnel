# Third-party notices

GeoTunnel is distributed under the GNU General Public License v3.0 (see
`LICENSE`) because it links sing-box, which is GPL-3.0.

| Component | Version (pinned in `core/go.mod`) | License | Notes |
|---|---|---|---|
| [sing-box](https://github.com/SagerNet/sing-box) | v1.14.4 | GPL-3.0-or-later, with an additional term: "no derivative work may use the name or imply association with this application without prior consent" | GeoTunnel is not affiliated with or endorsed by the sing-box project and must not be marketed under its name. |
| [sing](https://github.com/SagerNet/sing), [sing-tun](https://github.com/SagerNet/sing-tun) and other `github.com/sagernet/*` modules | see `core/go.mod` | GPL-3.0 / MIT (per module) | |
| [Xray-core](https://github.com/XTLS/Xray-core) | v1.260327.0 | MPL-2.0 | Source of the linked version: the tag above. |
| [coder/websocket](https://github.com/coder/websocket) | v1.8.14 | ISC | CDP transport on Windows |
| [tailscale/go-winio](https://github.com/tailscale/go-winio) | see `core/go.mod` | MIT | Windows named pipe IPC |
| golang.org/x/sys, golang.org/x/text | see `core/go.mod` | BSD-3-Clause | |
| Go standard library and runtime | Go 1.26 | BSD-3-Clause | |

The complete list of Go modules compiled into the core is `core/go.mod` +
`core/go.sum`. To regenerate a full per-module license report:

```bash
cd core && go run github.com/google/go-licenses@latest report ./cmd/core ./mobile
```

Flutter, Dart packages and platform SDK components carry their own licenses;
`flutter build` bundles them into the app's "Licenses" page automatically.
