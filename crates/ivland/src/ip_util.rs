use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket};
use ivlan_rpc::IpAddrs;

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            (chunk[0] as u16) << 8
        };
        sum += word as u32;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn recalculate_tcp_checksum_ipv4(
    buf: &mut [u8],
    len: usize,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    tcp_start: usize,
) {
    let tcp_len = len - tcp_start;

    // Zero out checksum field
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]);

    // Build pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + tcp_len(2)
    let mut pseudo = Vec::with_capacity(12 + tcp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP protocol
    pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&buf[tcp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv4(
    buf: &mut [u8],
    len: usize,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    udp_start: usize,
) {
    let udp_len = len - udp_start;

    // Zero out checksum field (only if it's non-zero, IPv4 UDP can have 0 checksum)
    let checksum_offset = udp_start + 6;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17); // UDP protocol
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());

    // Save and zero checksum
    let _saved_checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

    pseudo.extend_from_slice(&buf[udp_start..len]);

    let mut checksum = calculate_checksum(&pseudo);
    if checksum == 0 {
        checksum = 0xffff; // For IPv4, 0 means no checksum, so use 0xffff
    }

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_tcp_checksum_ipv6(
    buf: &mut [u8],
    len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    tcp_start: usize,
) {
    let tcp_len = len - tcp_start;

    // Zero out checksum field
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&[0, 0]);

    // Build pseudo-header: src(16) + dst(16) + payload_len(4) + zeros(3) + next_header(1)
    let mut pseudo = Vec::with_capacity(40 + tcp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]); // zeros + TCP protocol
    pseudo.extend_from_slice(&buf[tcp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    buf[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv6(
    buf: &mut [u8],
    len: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    udp_start: usize,
) {
    let udp_len = len - udp_start;
    let checksum_offset = udp_start + 6;

    // Build pseudo-header
    let mut pseudo = Vec::with_capacity(40 + udp_len);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]); // zeros + UDP protocol

    // Zero checksum
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

    pseudo.extend_from_slice(&buf[udp_start..len]);

    let checksum = calculate_checksum(&pseudo);
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

pub fn patch_packet_addresses(
    buf: &mut [u8],
    len: usize,
    src: IpAddrs,
    dst: IpAddrs,
) -> anyhow::Result<Option<(IpAddr, IpAddr)>> {
    let Ok(SlicedPacket { net, .. }) = SlicedPacket::from_ip(&buf[..len]) else {
        anyhow::bail!("Bad packet");
    };

    match net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header_len = (ipv4.header().ihl() as usize) * 4;
            let protocol = ipv4.header().protocol().0;

            let src_offset = 12;
            let dst_offset = 16;
            let checksum_offset = 10;

            buf[src_offset..src_offset + 4].copy_from_slice(&src.v4.octets());
            buf[dst_offset..dst_offset + 4].copy_from_slice(&dst.v4.octets());
            buf[checksum_offset..checksum_offset + 2].copy_from_slice(&[0, 0]);

            let mut sum: u32 = 0;
            for i in (0..header_len).step_by(2) {
                let word = u16::from_be_bytes([buf[i], buf[i + 1]]);
                sum += word as u32;
            }
            while (sum >> 16) > 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let checksum = !sum as u16;
            buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

            // Recalculate TCP/UDP checksums if present
            match protocol {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv4(buf, len, src.v4, dst.v4, header_len);
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv4(buf, len, src.v4, dst.v4, header_len);
                }
                _ => {}
            }

            Ok(Some((IpAddr::V4(src.v4), IpAddr::V4(dst.v4))))
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let src_offset = 8;
            let dst_offset = 24;
            let next_header = ipv6.header().next_header().0;

            buf[src_offset..src_offset + 16].copy_from_slice(&src.v6.octets());
            buf[dst_offset..dst_offset + 16].copy_from_slice(&dst.v6.octets());

            // Recalculate TCP/UDP checksums if present
            // IPv6 header is always 40 bytes
            let transport_start = 40;
            match next_header {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv6(buf, len, src.v6, dst.v6, transport_start);
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv6(buf, len, src.v6, dst.v6, transport_start);
                }
                _ => {}
            }

            Ok(Some((IpAddr::V6(src.v6), IpAddr::V6(dst.v6))))
        }
        _ => Ok(None),
    }
}
