# VPN 客户端 Makefile

.PHONY: build run clean test deps

# 目标
TARGET := vpn-client

# Go 参数
GOFMT := gofmt
GO := go
GOFLAGS := -v

# 构建
build: deps
	@echo "Building $(TARGET)..."
	cd $(TARGET) && $(GO) build $(GOFLAGS) -o ../bin/$(TARGET) .

# 运行
run: build
	@echo "Running $(TARGET)..."
	./bin/$(TARGET) -config=$(TARGET)/config.toml

# 安装依赖
deps:
	@echo "Installing dependencies..."
	cd $(TARGET) && $(GO) mod download
	cd $(TARGET) && $(GO) mod tidy

# 清理
clean:
	@echo "Cleaning..."
	rm -f bin/$(TARGET)

# 测试
test:
	@echo "Running tests..."
	cd $(TARGET) && $(GO) test -v ./...

# 格式化代码
fmt:
	@echo "Formatting code..."
	$(GOFMT) -w $(TARGET)/

# 交叉编译
build-linux:
	@echo "Building for Linux..."
	cd $(TARGET) && GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o ../bin/$(TARGET)-linux-amd64 .

build-windows:
	@echo "Building for Windows..."
	cd $(TARGET) && GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o ../bin/$(TARGET)-windows-amd64.exe .

build-darwin:
	@echo "Building for macOS..."
	cd $(TARGET) && GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o ../bin/$(TARGET)-darwin-amd64 .

# 帮助
help:
	@echo "Available targets:"
	@echo "  build         - Build the VPN client"
	@echo "  run           - Build and run the VPN client"
	@echo "  deps          - Install dependencies"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  fmt           - Format code"
	@echo "  build-linux   - Cross-compile for Linux"
	@echo "  build-windows - Cross-compile for Windows"
	@echo "  build-darwin  - Cross-compile for macOS"
