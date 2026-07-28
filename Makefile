VERSION=development
DOCKER_COMPOSE ?= docker compose

.PHONY: default zip lint format test test-unit test-integration test-race test-smoke \
	test-youtube test-ci vuln verify docker-run docker-build-run docker-stop

default:
	@echo "=============Building binaries============="

	# Linux 386
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/linux_386/simple-proxy main.go
	cp LICENSE dist/linux_386/LICENSE

	# Linux amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/linux_amd64/simple-proxy main.go
	cp LICENSE dist/linux_amd64/LICENSE

	# Linux arm
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/linux_arm/simple-proxy main.go
	cp LICENSE dist/linux_arm/LICENSE

	# Linux arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/linux_arm64/simple-proxy main.go
	cp LICENSE dist/linux_arm64/LICENSE

	# Darwin amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/darwin_amd64/simple-proxy main.go
	cp LICENSE dist/darwin_amd64/LICENSE

	# Darwin arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/darwin_arm64/simple-proxy main.go
	cp LICENSE dist/darwin_arm64/LICENSE

	# Windows 386
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/windows_386/simple-proxy.exe main.go
	cp LICENSE dist/windows_386/LICENSE

	# Windows amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-X 'main.Version=$(VERSION)'" -o dist/windows_amd64/simple-proxy.exe main.go
	cp LICENSE dist/windows_amd64/LICENSE

zip:
	@echo "=============Zipping binaries============="
	zip -r -j dist/simple-proxy_linux_386.zip dist/linux_386
	zip -r -j dist/simple-proxy_linux_amd64.zip dist/linux_amd64
	zip -r -j dist/simple-proxy_linux_arm.zip dist/linux_arm
	zip -r -j dist/simple-proxy_linux_arm64.zip dist/linux_arm64
	zip -r -j dist/simple-proxy_darwin_amd64.zip dist/darwin_amd64
	zip -r -j dist/simple-proxy_darwin_arm64.zip dist/darwin_arm64
	zip -r -j dist/simple-proxy_windows_386.zip dist/windows_386
	zip -r -j dist/simple-proxy_windows_amd64.zip dist/windows_amd64

lint:
	@echo "=============Linting============="
	go run honnef.co/go/tools/cmd/staticcheck@v0.6.0 ./...

format:
	@echo "=============Formatting============="
	gofmt -s -w main.go main_test.go proxy/*.go
	go mod tidy

test:
	@echo "=============Running all test layers============="
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-smoke

test-unit:
	@echo "=============Running unit tests============="
	go test . ./proxy

test-integration:
	@echo "=============Running integration tests============="
	go test ./integration

test-race:
	@echo "=============Running tests with race detector============="
	go test -race ./...

test-smoke:
	@echo "=============Running smoke test============="
	./scripts/smoke-test.sh

test-youtube:
	@echo "=============Testing YouTube through the proxy============="
	./scripts/youtube-connect-test.sh

test-ci: lint
	@echo "=============Checking formatting============="
	test -z "$$(gofmt -l .)"
	go vet ./...
	$(MAKE) test

vuln:
	@echo "=============Scanning for known vulnerabilities============="
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

verify:
	@echo "=============Checking formatting============="
	test -z "$$(gofmt -l .)"
	go vet ./...
	$(MAKE) test-race
	$(MAKE) test-smoke
	$(MAKE) vuln

docker-run:
	@echo "=============Starting Docker services============="
	$(DOCKER_COMPOSE) up --detach --no-build

docker-build-run:
	@echo "=============Building and starting Docker services============="
	$(DOCKER_COMPOSE) up --detach --build

docker-stop:
	@echo "=============Stopping Docker services============="
	$(DOCKER_COMPOSE) stop
