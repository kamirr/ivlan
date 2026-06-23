use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{NetSlice, SlicedPacket};
use ivlan_rpc::IpAddrs;

pub const ROUTER_MULTICAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0002);

fn csum_replace_16(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!checksum as u32 & 0xffff) + (!old as u32 & 0xffff) + (new as u32);

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    !(sum as u16)
}

fn recalculate_tcp_checksum_ipv4(
    buf: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_src: Ipv4Addr,
    new_dst: Ipv4Addr,
    tcp_start: usize,
) {
    let checksum_offset = tcp_start + 16;
    let mut checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);

    // Replace each 16-bit word of old addresses with new addresses
    let old_src_words = old_src.octets();
    let old_dst_words = old_dst.octets();
    let new_src_words = new_src.octets();
    let new_dst_words = new_dst.octets();

    // Source address - two 16-bit words
    let old_src_w1 = u16::from_be_bytes([old_src_words[0], old_src_words[1]]);
    let new_src_w1 = u16::from_be_bytes([new_src_words[0], new_src_words[1]]);
    checksum = csum_replace_16(checksum, old_src_w1, new_src_w1);

    let old_src_w2 = u16::from_be_bytes([old_src_words[2], old_src_words[3]]);
    let new_src_w2 = u16::from_be_bytes([new_src_words[2], new_src_words[3]]);
    checksum = csum_replace_16(checksum, old_src_w2, new_src_w2);

    // Destination address - two 16-bit words
    let old_dst_w1 = u16::from_be_bytes([old_dst_words[0], old_dst_words[1]]);
    let new_dst_w1 = u16::from_be_bytes([new_dst_words[0], new_dst_words[1]]);
    checksum = csum_replace_16(checksum, old_dst_w1, new_dst_w1);

    let old_dst_w2 = u16::from_be_bytes([old_dst_words[2], old_dst_words[3]]);
    let new_dst_w2 = u16::from_be_bytes([new_dst_words[2], new_dst_words[3]]);
    checksum = csum_replace_16(checksum, old_dst_w2, new_dst_w2);

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv4(
    buf: &mut [u8],
    old_src: Ipv4Addr,
    old_dst: Ipv4Addr,
    new_src: Ipv4Addr,
    new_dst: Ipv4Addr,
    udp_start: usize,
) {
    let checksum_offset = udp_start + 6;
    let old_checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);

    // For UDP, 0 means no checksum, so skip if it was 0
    if old_checksum == 0 {
        return;
    }

    let mut checksum = old_checksum;

    // Replace each 16-bit word of old addresses with new addresses
    let old_src_words = old_src.octets();
    let old_dst_words = old_dst.octets();
    let new_src_words = new_src.octets();
    let new_dst_words = new_dst.octets();

    // Source address - two 16-bit words
    let old_src_w1 = u16::from_be_bytes([old_src_words[0], old_src_words[1]]);
    let new_src_w1 = u16::from_be_bytes([new_src_words[0], new_src_words[1]]);
    checksum = csum_replace_16(checksum, old_src_w1, new_src_w1);

    let old_src_w2 = u16::from_be_bytes([old_src_words[2], old_src_words[3]]);
    let new_src_w2 = u16::from_be_bytes([new_src_words[2], new_src_words[3]]);
    checksum = csum_replace_16(checksum, old_src_w2, new_src_w2);

    // Destination address - two 16-bit words
    let old_dst_w1 = u16::from_be_bytes([old_dst_words[0], old_dst_words[1]]);
    let new_dst_w1 = u16::from_be_bytes([new_dst_words[0], new_dst_words[1]]);
    checksum = csum_replace_16(checksum, old_dst_w1, new_dst_w1);

    let old_dst_w2 = u16::from_be_bytes([old_dst_words[2], old_dst_words[3]]);
    let new_dst_w2 = u16::from_be_bytes([new_dst_words[2], new_dst_words[3]]);
    checksum = csum_replace_16(checksum, old_dst_w2, new_dst_w2);

    if checksum == 0 {
        checksum = 0xffff; // For IPv4, 0 means no checksum, so use 0xffff
    }

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_tcp_checksum_ipv6(
    buf: &mut [u8],
    old_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_src: Ipv6Addr,
    new_dst: Ipv6Addr,
    tcp_start: usize,
) {
    let checksum_offset = tcp_start + 16;
    let mut checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);

    // Replace each 16-bit word of old addresses with new addresses
    let old_src_words = old_src.segments();
    let old_dst_words = old_dst.segments();
    let new_src_words = new_src.segments();
    let new_dst_words = new_dst.segments();

    // Source address - 4 16-bit words
    for i in 0..8 {
        checksum = csum_replace_16(checksum, old_src_words[i], new_src_words[i]);
    }

    // Destination address - 4 16-bit words
    for i in 0..8 {
        checksum = csum_replace_16(checksum, old_dst_words[i], new_dst_words[i]);
    }

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

fn recalculate_udp_checksum_ipv6(
    buf: &mut [u8],
    old_src: Ipv6Addr,
    old_dst: Ipv6Addr,
    new_src: Ipv6Addr,
    new_dst: Ipv6Addr,
    udp_start: usize,
) {
    let checksum_offset = udp_start + 6;
    let old_checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);

    // IPv6 UDP always requires checksum, but skip if it's 0 (shouldn't happen)
    if old_checksum == 0 {
        return;
    }

    let mut checksum = old_checksum;

    // Replace each 16-bit word of old addresses with new addresses
    let old_src_words = old_src.segments();
    let old_dst_words = old_dst.segments();
    let new_src_words = new_src.segments();
    let new_dst_words = new_dst.segments();

    // Source address - 4 16-bit words
    for i in 0..8 {
        checksum = csum_replace_16(checksum, old_src_words[i], new_src_words[i]);
    }

    // Destination address - 4 16-bit words
    for i in 0..8 {
        checksum = csum_replace_16(checksum, old_dst_words[i], new_dst_words[i]);
    }

    if checksum == 0 {
        checksum = 0xffff;
    }

    buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

pub fn patch_packet_addresses(
    buf: &mut [u8],
    src: IpAddrs,
    dst: IpAddrs,
) -> anyhow::Result<Option<(IpAddr, IpAddr)>> {
    let net = SlicedPacket::from_ip(&buf)?.net;

    match net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header_len = (ipv4.header().ihl() as usize) * 4;
            let protocol = ipv4.header().protocol().0;

            let src_offset = 12;
            let dst_offset = 16;
            let checksum_offset = 10;

            // Capture old addresses before modification
            let old_src = Ipv4Addr::new(
                buf[src_offset],
                buf[src_offset + 1],
                buf[src_offset + 2],
                buf[src_offset + 3],
            );
            let old_dst = Ipv4Addr::new(
                buf[dst_offset],
                buf[dst_offset + 1],
                buf[dst_offset + 2],
                buf[dst_offset + 3],
            );

            // Update addresses
            buf[src_offset..src_offset + 4].copy_from_slice(&src.v4.octets());
            buf[dst_offset..dst_offset + 4].copy_from_slice(&dst.v4.octets());

            // Incrementally update IPv4 header checksum
            let mut checksum = u16::from_be_bytes([buf[checksum_offset], buf[checksum_offset + 1]]);

            // Replace each 16-bit word
            let old_src_bytes = old_src.octets();
            let new_src_bytes = src.v4.octets();
            let old_src_w1 = u16::from_be_bytes([old_src_bytes[0], old_src_bytes[1]]);
            let new_src_w1 = u16::from_be_bytes([new_src_bytes[0], new_src_bytes[1]]);
            checksum = csum_replace_16(checksum, old_src_w1, new_src_w1);

            let old_src_w2 = u16::from_be_bytes([old_src_bytes[2], old_src_bytes[3]]);
            let new_src_w2 = u16::from_be_bytes([new_src_bytes[2], new_src_bytes[3]]);
            checksum = csum_replace_16(checksum, old_src_w2, new_src_w2);

            let old_dst_bytes = old_dst.octets();
            let new_dst_bytes = dst.v4.octets();
            let old_dst_w1 = u16::from_be_bytes([old_dst_bytes[0], old_dst_bytes[1]]);
            let new_dst_w1 = u16::from_be_bytes([new_dst_bytes[0], new_dst_bytes[1]]);
            checksum = csum_replace_16(checksum, old_dst_w1, new_dst_w1);

            let old_dst_w2 = u16::from_be_bytes([old_dst_bytes[2], old_dst_bytes[3]]);
            let new_dst_w2 = u16::from_be_bytes([new_dst_bytes[2], new_dst_bytes[3]]);
            checksum = csum_replace_16(checksum, old_dst_w2, new_dst_w2);

            buf[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());

            // Recalculate TCP/UDP checksums if present
            match protocol {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv4(
                        buf, old_src, old_dst, src.v4, dst.v4, header_len,
                    );
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv4(
                        buf, old_src, old_dst, src.v4, dst.v4, header_len,
                    );
                }
                _ => {}
            }

            Ok(Some((IpAddr::V4(src.v4), IpAddr::V4(dst.v4))))
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let src_offset = 8;
            let dst_offset = 24;
            let next_header = ipv6.header().next_header().0;

            // Capture old addresses before modification
            let mut old_src_bytes = [0u8; 16];
            let mut old_dst_bytes = [0u8; 16];
            old_src_bytes.copy_from_slice(&buf[src_offset..src_offset + 16]);
            old_dst_bytes.copy_from_slice(&buf[dst_offset..dst_offset + 16]);
            let old_src = Ipv6Addr::from(old_src_bytes);
            let old_dst = Ipv6Addr::from(old_dst_bytes);

            buf[src_offset..src_offset + 16].copy_from_slice(&src.v6.octets());
            buf[dst_offset..dst_offset + 16].copy_from_slice(&dst.v6.octets());

            // Recalculate TCP/UDP checksums if present
            // IPv6 header is always 40 bytes
            let transport_start = 40;
            match next_header {
                6 => {
                    // TCP
                    recalculate_tcp_checksum_ipv6(
                        buf,
                        old_src,
                        old_dst,
                        src.v6,
                        dst.v6,
                        transport_start,
                    );
                }
                17 => {
                    // UDP
                    recalculate_udp_checksum_ipv6(
                        buf,
                        old_src,
                        old_dst,
                        src.v6,
                        dst.v6,
                        transport_start,
                    );
                }
                _ => {}
            }

            Ok(Some((IpAddr::V6(src.v6), IpAddr::V6(dst.v6))))
        }
        _ => Ok(None),
    }
}
