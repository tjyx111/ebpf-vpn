use aya::{Bpf, BpfLoader};
use aya_log::BpfLogger;
use clap::Parser;
use log::{error, info};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "xdp-loader")]
#[command(about = "Rust XDP UDP Echo 加载程序", long_about = None)]
#[command(author = "Your Name")]
struct Args {
    /// 网卡接口名称
    #[arg(short, long, default_value = "lo")]
    iface: String,

    /// XDP 程序文件路径
    #[arg(short, long)]
    program: Option<PathBuf>,
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    info!("🚀 Rust XDP UDP Echo Loader");
    info!("📡 接口: {}", args.iface);
    info!("🎯 UDP 端口: 28080");

    // 确定 BPF 文件路径
    let bpf_file = if let Some(prog) = args.program {
        prog
    } else {
        // 默认路径：xdp-prog 编译输出
        PathBuf::from("xdp-prog/target/bpfel-unknown-none/release/xdp-prog.bpf")
    };

    if !bpf_file.exists() {
        error!("❌ 找不到 BPF 文件: {}", bpf_file.display());
        error!("💡 请先运行: cd xdp-prog && cargo build --release");
        return Ok(());
    }

    info!("📂 加载 BPF 文件: {}", bpf_file.display());

    // 加载 eBPF 程序
    let mut bpf = match Bpf::load(&bpf_file) {
        Ok(bpf) => bpf,
        Err(e) => {
            error!("❌ 加载 BPF 失败: {}", e);
            return Err(e.into());
        }
    };

    // 初始化日志
    if let Err(e) = BpfLogger::init(&mut bpf) {
        error!("❌ 初始化日志失败: {}", e);
        return Err(e.into());
    }

    // 附加 XDP 程序到网卡
    let program = match bpf.program_mut("udp_echo") {
        Some(prog) => prog,
        None => {
            error!("❌ 未找到 'udp_echo' 程序");
            error!("💡 确认 BPF 文件包含此程序");
            return Ok(());
        }
    };

    if let Err(e) = program.load(&args.iface, Default::default()) {
        error!("❌ 附加 XDP 程序失败: {}", e);
        error!("💡 尝试先卸载: sudo ip link set {} xdpgeneric off", args.iface);
        return Err(e.into());
    }

    info!("✅ XDP 程序加载成功!");
    info!("📝 监听地址: 127.0.0.1:28080");
    info!("\n🧪 测试命令:");
    info!("   nc -u 127.0.0.1 28080");
    info!("\n⏹️  按 Ctrl+C 退出程序");

    // 保持程序运行
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
