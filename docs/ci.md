# CI for the Go core

Two GitHub Actions workflows live in `.github/workflows/`.

## `core-ci.yml` — every pull request and push to `main`

Runs when anything under `core/` (or the workflow itself) changes.

| Job | What it checks |
|---|---|
| `lint` | `gofmt`, `go mod tidy -diff`, `go mod verify`, then `go vet` and golangci-lint (config: `core/.golangci.yml`) for linux, darwin, windows and android with `CGO_ENABLED=0`, so platform-specific files are checked even though the job runs on Linux. |
| `test` | `go test ./...` on Ubuntu, macOS and Windows (`-race` on Ubuntu and macOS). This includes the end-to-end tests through local Xray and sing-box servers and the Chromium container tests, which use the Chrome preinstalled on the runners. |
| `sidecar` | Cross-compiles `cmd/core` for windows/darwin/linux × amd64/arm64 with `CGO_ENABLED=0`; binaries are uploaded as 7-day artifacts. |
| `android-aar` | `gomobile bind` of `core/mobile` into `core.aar` with the runner's Android NDK. |

The iOS `.xcframework` is built only by the release workflow, to keep macOS
runner minutes off pull requests.

## `core-release.yml` — tags `v*`, or run manually

Builds the six sidecars, a universal macOS sidecar (`lipo`), `core.aar` and
`Core.xcframework.zip`. For a `v*` tag it then creates a GitHub release with
those files and a `SHA256SUMS` file. A manual run builds the same artifacts
without publishing anything.

To release: `git tag v0.1.0 && git push origin v0.1.0`.

## Pinned tools

| Tool | Where the version lives |
|---|---|
| Go | `GO_VERSION` in both workflows (`1.26.x`, latest patch); the minimum is the `go` line in `core/go.mod`. |
| gomobile, gobind | `tool` block in `core/go.mod`. CI builds both from there rather than running `gomobile init`, which would install `gobind@latest`. |
| golangci-lint | `GOLANGCI_LINT_VERSION` in `core-ci.yml` and the `Makefile`. |

## Notes

- Ubuntu 24.04 runners block the unprivileged user namespaces Chrome's
  sandbox needs, so the Linux test job sets
  `GEOTUNNEL_TEST_BROWSER_ARGS=--no-sandbox`. Only the tests read it.
- On Windows the container tests use Chrome's debug-port transport, because
  `--remote-debugging-pipe` needs inherited file descriptors.
- `make lint`, `make test`, `make android-aar` and `make ios-xcframework` run
  the same commands locally.
