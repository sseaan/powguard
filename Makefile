.PHONY: all build test race vet fmt lint clean linux release check

GO      ?= go
BIN     ?= powguard
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS ?= -s -w -X main.version=$(VERSION)

all: build

## 本机构建
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/powguard
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o capsolve ./tools/capsolve

## 生产构建：静态、无 CGO、Linux amd64
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/powguard-linux-amd64 ./cmd/powguard
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/capsolve-linux-amd64 ./tools/capsolve
	@file dist/powguard-linux-amd64
	@sha256sum dist/powguard-linux-amd64 | tee dist/powguard-linux-amd64.sha256

release: linux
	@echo "产物：dist/powguard-linux-amd64（静态二进制，可直接 scp 到服务器）"

test:
	$(GO) test ./... -count=1

## 并发安全与数据竞争
race:
	$(GO) test -race ./... -count=1

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w cmd internal web tools

## 协议互操作（官方 → Go / Go → 官方），需要 node 与 tools/oracle 已安装
oracle:
	@test -d tools/oracle/node_modules/@cap.js/server || { echo "缺少 tools/oracle 依赖：cd tools/oracle && npm ci" >&2; exit 1; }
	cd tools/oracle && node gen-fixtures.mjs
	$(GO) test ./internal/protocol/... -count=1

check: fmt vet race
	@echo "check 通过（fmt + vet + race）"

clean:
	rm -rf dist $(BIN) capsolve
