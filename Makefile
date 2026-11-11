# Developer shortcuts for the Go core. CI runs the same commands
# (.github/workflows/core-ci.yml); see docs/ci.md.
TAGS ?= with_gvisor,with_quic,with_utls,with_clash_api
GO   ?= go
GOLANGCI_LINT_VERSION ?= v2.15.0
TOOLS := $(CURDIR)/dist/tools

.PHONY: test lint core tools android-aar ios-xcframework

test:            ## Go tests (Chrome-based container tests skip if no browser)
	cd core && $(GO) test -tags "$(TAGS)" ./...

lint:            ## gofmt, go.mod tidiness, golangci-lint (pinned version)
	cd core && test -z "$$(gofmt -l .)" && $(GO) mod tidy -diff && \
		$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run ./...

core:            ## desktop sidecar for this machine
	cd core && CGO_ENABLED=0 $(GO) build -trimpath -tags "$(TAGS)" -ldflags "-s -w" -o ../dist/core ./cmd/core

tools:           ## gomobile + gobind at the versions pinned in core/go.mod
	cd core && $(GO) build -o $(TOOLS)/ golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind

android-aar: tools ## needs ANDROID_NDK_HOME and a JDK
	cd core && PATH="$(TOOLS):$$PATH" gomobile bind -target=android -androidapi 21 -javapkg app.geotunnel \
		-tags "$(TAGS)" -trimpath -ldflags "-s -w" -o ../dist/core.aar ./mobile

ios-xcframework: tools ## needs Xcode
	cd core && PATH="$(TOOLS):$$PATH" gomobile bind -target=ios,iossimulator -prefix GT \
		-tags "$(TAGS)" -trimpath -ldflags "-s -w" -o ../dist/Core.xcframework ./mobile
