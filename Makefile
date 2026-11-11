# Developer shortcuts. CI uses the same commands (see .github/workflows).
TAGS ?= with_gvisor,with_quic,with_utls,with_clash_api
GO   ?= go

.PHONY: test core webinject-test android-aar ios-xcframework app-bootstrap

test:            ## Go tests (Chrome-based webapp tests skip if no browser)
	cd core && $(GO) test -tags "$(TAGS)" ./...

core:            ## desktop sidecar for this machine
	cd core && CGO_ENABLED=0 $(GO) build -trimpath -tags "$(TAGS)" -ldflags "-s -w" -o ../dist/core ./cmd/core

webinject-test:  ## JS override script tests in headless Chrome
	cd webinject && node --test test/

android-aar:     ## needs ANDROID_NDK_HOME and gomobile
	cd core && gomobile bind -target=android -androidapi 21 -javapkg app.geotunnel -tags "$(TAGS)" \
		-trimpath -ldflags "-s -w" -o ../app/android/app/libs/core.aar ./mobile

ios-xcframework: ## needs Xcode and gomobile
	cd core && gomobile bind -target=ios,iossimulator -prefix GT -tags "$(TAGS)" \
		-trimpath -ldflags "-s -w" -o ../app/ios/Core.xcframework ./mobile

app-bootstrap:   ## generate the standard Flutter runner files around our sources
	cd app && ./tool/bootstrap.sh
