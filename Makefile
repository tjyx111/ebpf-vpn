# Makefile for ebpf-vpn

# 变量定义
BINARY_NAME = ebpf-vpn
BPF_DIR = internal/bpf
CMD_DIR = cmd/xdp-loader
GO = go
CLANG = clang

# 默认目标
.DEFAULT_GOAL := build

.PHONY: help
help:
	@echo "ebpf-vpn Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build        - 编译 eBPF 程序和 Go 程序"
	@echo "  make bpf          - 仅编译 eBPF 程序"
	@echo "  make go           - 仅编译 Go 程序"
	@echo "  make clean        - 清理所有编译产物"
	@echo "  make run          - 编译并运行程序 (需要 sudo)"
	@echo "  make help         - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make build        # 完整编译"
	@echo "  make run          # 编译并运行 (使用默认配置)"

.PHONY: build
build: bpf go
	@echo "编译完成: $(BINARY_NAME)"

.PHONY: bpf
bpf:
	@echo "编译 eBPF 程序..."
	cd $(BPF_DIR) && $(GO) generate
	@echo "eBPF 程序编译完成"

.PHONY: go
go:
	@echo "编译 Go 程序..."
	$(GO) build -o $(BINARY_NAME) ./$(CMD_DIR)/
	@echo "Go 程序编译完成"

.PHONY: clean
clean:
	@echo "清理编译产物..."
	rm -f $(BINARY_NAME)
	rm -f $(BPF_DIR)/bpf_bpfeb.o
	rm -f $(BPF_DIR)/bpf_bpfel.o
	rm -f $(BPF_DIR)/bpf_bpfeb.go
	rm -f $(BPF_DIR)/bpf_bpfel.go
	@echo "清理完成"

.PHONY: run
run: build
	@echo "运行 $(BINARY_NAME)..."
	sudo ./$(BINARY_NAME) -iface eth0 -config config.toml
