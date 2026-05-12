#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp::{self, XdpAction},
    macros::xdp,
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::info;

/// UDP Echo 监听端口（与现有 Go 程序一致）
const UDP_ECHO_PORT: u16 = 28080;

#[xdp]
pub fn udp_echo(ctx: XdpContext) -> u32 {
    match try_udp_echo(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp::XDP_PASS,
    }
}

fn try_udp_echo(ctx: XdpContext) -> Result<u32, u32> {
    // 1. 获取以太网头
    let eth = ctx.eth()?;
    let eth_proto = u16::from_be(eth.host_type());

    // 只处理 IPv4 (0x0800)
    if eth_proto != 0x0800 {
        return Ok(xdp::XDP_PASS);
    }

    // 2. 获取 IP 头
    let ip = ctx.ip()?;
    let ip_proto = ip.protocol;

    // 只处理 UDP (17)
    if ip_proto != 17 {
        return Ok(xdp::XDP_PASS);
    }

    // 3. 获取 UDP 头
    let udp = ctx.udp()?;
    let dest_port = u16::from_be(udp.dest);

    // 4. 检查目标端口
    if dest_port != UDP_ECHO_PORT {
        return Ok(xdp::XDP_PASS);
    }

    // 5. UDP Echo: 交换源和目的地址
    // 交换 MAC 地址
    let src_mac = eth.src_addr;
    let dst_mac = eth.dst_addr;
    unsafe {
        *eth.src_addr = dst_mac;
        *eth.dst_addr = src_mac;
    }

    // 交换 IP 地址
    let src_ip = ip.src_addr;
    let dst_ip = ip.dst_addr;
    unsafe {
        *ip.src_addr = dst_ip;
        *ip.dst_addr = src_ip;
    }

    // 交换 UDP 端口
    let src_port = udp.source;
    let dest_port = udp.dest;
    unsafe {
        *udp.source = dest_port;
        *udp.dest = src_port;
    }

    // 6. 记录日志
    info!(&ctx, "UDP Echo: sent packet back from port {}", dest_port);

    // 7. 从原接口返回数据包
    Ok(xdp::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
