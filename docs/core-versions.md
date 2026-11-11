# Core versions and how to update them

| Core | Pinned | Why this one |
|---|---|---|
| Xray-core | `github.com/xtls/xray-core v1.260327.0` | Latest Go-module tag (Xray publishes `v1.YYMMDD.N` tags alongside `v26.x` releases). Requires Go 1.26. |
| sing-box | `github.com/sagernet/sing-box v1.14.4` | Latest stable at the time of writing. |
| Go toolchain | 1.26 (`go` line in `core/go.mod`) | Minimum required by Xray-core. |

Both cores are linked into one Go binary / gomobile library. Their shared
dependencies resolve by Go's minimal version selection; the build in CI
(`go build -tags with_gvisor,with_quic,with_utls,with_clash_api ./...`) is the
compatibility check.

## Behaviour that depends on these versions (verified in source)

GeoTunnel's engine selection (`core/config/model.go`, `Outbound.Engine`) is
based on what the pinned versions actually support:

- **Xray-core removed the `h2`/`http` and `quic` transports**
  (`infra/conf/transport_internet.go`, `TransportProtocol.Build` returns
  `PrintRemovedFeatureError`). Links using them run on sing-box.
- **Xray-core rejects `tlsSettings.allowInsecure` after 2026-06-01** and
  wants `pinnedPeerCertSha256` instead. Insecure TLS links therefore run on
  sing-box, except XHTTP/mKCP ones, which no engine can run; the import shows
  an error asking for a pinned hash (`pcs=` link parameter).
- **sing-box has no XHTTP transport** (no `xhttp` anywhere in v1.14.4), so
  XHTTP always runs on Xray-core.
- **Xray-core has no SIP003 plugins**; Shadowsocks with `plugin=` runs on
  sing-box (`obfs-local`, `v2ray-plugin`).
- Hysteria2 and TUIC run on sing-box.
- sing-box 1.12+ typed DNS servers (`{"type":"https","server":...}`) and
  `route.default_domain_resolver` are used; the legacy DNS format is not.

## Updating

1. `cd core && go get github.com/xtls/xray-core@<tag> github.com/sagernet/sing-box@<tag> && go mod tidy`
2. Re-check the bullet points above against the new sources (grep
   `PrintRemovedFeatureError` in Xray's `infra/conf`, and `option/` in
   sing-box for renamed fields).
3. `go test -tags with_gvisor,with_quic,with_utls,with_clash_api ./...` — in
   particular `engine.TestEveryFixtureBuildsValidCoreConfigs` and
   `engine.TestTunConfigsParse` feed every generated config through the real
   loaders of both cores, and `engine.TestEndToEndThroughBothEngines` passes
   traffic through each engine.
4. Update this file and `THIRD_PARTY_NOTICES.md`.
