.PHONY: all build clean run test help

all: build

build:
	@echo "🔨 构建 Rust XDP 程序..."
	cd xdp-prog && cargo build --release
	@echo "✅ 构建完成"
	@echo "📂 BPF 文件: xdp-prog/target/bpfel-unknown-none/release/xdp-prog.bpf"

run:
	@echo "🚀 运行 XDP 加载程序..."
	cd xdp-loader && cargo run --release

test:
	@echo "🧪 测试 UDP Echo 功能..."
	@echo "在另一个终端运行: nc -u 127.0.0.1 28080"

clean:
	@echo "🧹 清理构建产物..."
	cd xdp-prog && cargo clean
	cd xdp-loader && cargo clean
	rm -f xdp-prog/target/bpfel-unknown-none/release/*.bpf

unload:
	@echo "⏹️  卸载 XDP 程序..."
	sudo ip link set lo xdpgeneric off 2>&1 || echo "未加载 XDP 程序"

help:
	@echo "Rust XDP UDP Echo Demo"
	@echo ""
	@echo "使用方法:"
	@echo "  make build   - 构建 XDP 程序"
	@echo "  make run     - 运行 XDP 程序"
	@echo "  make test    - 显示测试命令"
	@echo "  make clean   - 清理构建产物"
	@echo "  make unload  - 卸载 XDP 程序"
	@echo ""
	@echo "示例:"
	@echo "  make build && make run"
