// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use pal_async::DefaultDriver;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::Ipv6Packet;
use smoltcp::wire::Ipv6Repr;
use smoltcp::wire::TcpPacket;
use smoltcp::wire::TcpRepr;

const ETHERNET_HEADER_LEN: usize = 14;

struct TestClient {
    driver: DefaultDriver,
    received_packets: Vec<(Vec<u8>, ChecksumState)>,
}

impl TestClient {
    fn new(driver: DefaultDriver) -> Self {
        Self {
            driver,
            received_packets: Vec::new(),
        }
    }
}

impl Client for TestClient {
    fn driver(&self) -> &dyn Driver {
        &self.driver
    }

    fn recv(&mut self, data: &[u8], checksum: &ChecksumState) {
        self.received_packets.push((data.to_vec(), *checksum));
    }

    fn rx_mtu(&mut self) -> usize {
        1514
    }
}

/// Build a minimal TCP SYN packet inside an Ethernet/IPv4 frame.
fn build_ipv4_syn(
    buf: &mut [u8],
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
) -> usize {
    let tcp = TcpRepr {
        src_port: 44444,
        dst_port: 80,
        control: smoltcp::wire::TcpControl::Syn,
        seq_number: smoltcp::wire::TcpSeqNumber(1000),
        ack_number: None,
        window_len: 64240,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut eth = EthernetFrame::new_unchecked(buf);
    eth.set_src_addr(src_mac);
    eth.set_dst_addr(dst_mac);
    eth.set_ethertype(EthernetProtocol::Ipv4);

    let ip_repr = Ipv4Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.header_len(),
        hop_limit: 64,
    };
    let mut ipv4 = Ipv4Packet::new_unchecked(eth.payload_mut());
    ip_repr.emit(&mut ipv4, &ChecksumCapabilities::default());

    let mut tcp_pkt = TcpPacket::new_unchecked(ipv4.payload_mut());
    tcp.emit(
        &mut tcp_pkt,
        &src_ip.into(),
        &dst_ip.into(),
        &ChecksumCapabilities::default(),
    );
    tcp_pkt.fill_checksum(&src_ip.into(), &dst_ip.into());

    ETHERNET_HEADER_LEN + ipv4.total_len() as usize
}

/// Build a minimal TCP SYN packet inside an Ethernet/IPv6 frame.
fn build_ipv6_syn(
    buf: &mut [u8],
    src_mac: EthernetAddress,
    dst_mac: EthernetAddress,
    src_ip: Ipv6Address,
    dst_ip: Ipv6Address,
) -> usize {
    let tcp = TcpRepr {
        src_port: 44444,
        dst_port: 80,
        control: smoltcp::wire::TcpControl::Syn,
        seq_number: smoltcp::wire::TcpSeqNumber(1000),
        ack_number: None,
        window_len: 64240,
        window_scale: Some(7),
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    };

    let mut eth = EthernetFrame::new_unchecked(buf);
    eth.set_src_addr(src_mac);
    eth.set_dst_addr(dst_mac);
    eth.set_ethertype(EthernetProtocol::Ipv6);

    let ip_repr = Ipv6Repr {
        src_addr: src_ip,
        dst_addr: dst_ip,
        next_header: IpProtocol::Tcp,
        payload_len: tcp.header_len(),
        hop_limit: 64,
    };
    let mut ipv6 = Ipv6Packet::new_unchecked(eth.payload_mut());
    ip_repr.emit(&mut ipv6);

    let mut tcp_pkt = TcpPacket::new_unchecked(ipv6.payload_mut());
    tcp.emit(
        &mut tcp_pkt,
        &src_ip.into(),
        &dst_ip.into(),
        &ChecksumCapabilities::default(),
    );
    tcp_pkt.fill_checksum(&src_ip.into(), &dst_ip.into());

    ETHERNET_HEADER_LEN + smoltcp::wire::IPV6_HEADER_LEN + tcp.header_len()
}

fn assert_ipv4_not_looped_back(
    client: &TestClient,
    expected_src_ip: Ipv4Address,
    expected_dst_ip: Ipv4Address,
    description: &str,
) {
    assert!(
        !client.received_packets.iter().any(|(packet, _)| {
            let eth = EthernetFrame::new_unchecked(packet.as_slice());
            if eth.ethertype() != EthernetProtocol::Ipv4 {
                return false;
            }
            let ipv4 = Ipv4Packet::new_unchecked(eth.payload());
            ipv4.src_addr() == expected_src_ip && ipv4.dst_addr() == expected_dst_ip
        }),
        "{description} should not be looped back"
    );
}

fn assert_ipv6_not_looped_back(
    client: &TestClient,
    expected_src_ip: Ipv6Address,
    expected_dst_ip: Ipv6Address,
    description: &str,
) {
    assert!(
        !client.received_packets.iter().any(|(packet, _)| {
            let eth = EthernetFrame::new_unchecked(packet.as_slice());
            if eth.ethertype() != EthernetProtocol::Ipv6 {
                return false;
            }
            let ipv6 = Ipv6Packet::new_unchecked(eth.payload());
            ipv6.src_addr() == expected_src_ip && ipv6.dst_addr() == expected_dst_ip
        }),
        "{description} should not be looped back"
    );
}

fn assert_ipv4_looped_back(
    client: &TestClient,
    expected_src_mac: EthernetAddress,
    expected_dst_mac: EthernetAddress,
    expected_src_ip: Ipv4Address,
    expected_dst_ip: Ipv4Address,
) {
    assert_eq!(client.received_packets.len(), 1);
    let (packet, checksum) = &client.received_packets[0];
    assert!(checksum.ipv4);

    let eth = EthernetFrame::new_unchecked(packet.as_slice());
    assert_eq!(eth.src_addr(), expected_src_mac);
    assert_eq!(eth.dst_addr(), expected_dst_mac);
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);

    let ipv4 = Ipv4Packet::new_unchecked(eth.payload());
    assert_eq!(ipv4.src_addr(), expected_src_ip);
    assert_eq!(ipv4.dst_addr(), expected_dst_ip);
}

fn assert_ipv6_looped_back(
    client: &TestClient,
    expected_src_mac: EthernetAddress,
    expected_dst_mac: EthernetAddress,
    expected_src_ip: Ipv6Address,
    expected_dst_ip: Ipv6Address,
) {
    assert_eq!(client.received_packets.len(), 1);
    let (packet, _) = &client.received_packets[0];

    let eth = EthernetFrame::new_unchecked(packet.as_slice());
    assert_eq!(eth.src_addr(), expected_src_mac);
    assert_eq!(eth.dst_addr(), expected_dst_mac);
    assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);

    let ipv6 = Ipv6Packet::new_unchecked(eth.payload());
    assert_eq!(ipv6.src_addr(), expected_src_ip);
    assert_eq!(ipv6.dst_addr(), expected_dst_ip);
}

/// Verify that traffic to IPv4 loopback (127.0.0.1) is routed back to the guest
/// by default.
#[pal_async::async_test]
async fn ipv4_loopback_looped_back_by_default(driver: DefaultDriver) {
    let mut consomme = Consomme::new(ConsommeParams::new().unwrap());
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(127, 0, 0, 1),
    );
    consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE)
        .unwrap();
    assert_ipv4_looped_back(
        &client,
        gateway_mac,
        guest_mac,
        guest_ip,
        Ipv4Address::new(127, 0, 0, 1),
    );
}

/// Verify that traffic to IPv4 unspecified (0.0.0.0) is routed back to the
/// guest.
#[pal_async::async_test]
async fn ipv4_unspecified_looped_back(driver: DefaultDriver) {
    let mut consomme = Consomme::new(ConsommeParams::new().unwrap());
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(0, 0, 0, 0),
    );
    consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE)
        .unwrap();
    assert_ipv4_looped_back(
        &client,
        gateway_mac,
        guest_mac,
        guest_ip,
        Ipv4Address::new(0, 0, 0, 0),
    );
}

/// Verify that traffic to IPv4 link-local (169.254.x.x) is not blocked.
#[pal_async::async_test]
async fn ipv4_link_local_not_blocked(driver: DefaultDriver) {
    let mut consomme = Consomme::new(ConsommeParams::new().unwrap());
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(169, 254, 1, 1),
    );
    let result = consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE);
    let _ = result;
    assert_ipv4_not_looped_back(
        &client,
        guest_ip,
        Ipv4Address::new(169, 254, 1, 1),
        "link-local traffic",
    );
}

/// Verify that traffic to the configured IPv4 subnet is not blocked.
#[pal_async::async_test]
async fn ipv4_local_subnet_not_blocked(driver: DefaultDriver) {
    let mut consomme = Consomme::new(ConsommeParams::new().unwrap());
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(10, 0, 0, 42),
    );
    let result = consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE);
    let _ = result;
    assert_ipv4_not_looped_back(
        &client,
        guest_ip,
        Ipv4Address::new(10, 0, 0, 42),
        "local subnet traffic",
    );
}

/// Verify that loopback traffic is allowed when opted in.
#[pal_async::async_test]
async fn ipv4_loopback_allowed_when_opted_in(driver: DefaultDriver) {
    let mut consomme = Consomme::new({
        let mut params = ConsommeParams::new().unwrap();
        params.allow_host_local_access = true;
        params
    });
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(127, 0, 0, 1),
    );
    let result = consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE);
    let _ = result;
    assert_ipv4_not_looped_back(
        &client,
        guest_ip,
        Ipv4Address::new(127, 0, 0, 1),
        "loopback traffic when opted in",
    );
}

/// Verify that traffic to IPv6 loopback (::1) is routed back to the guest by
/// default.
#[pal_async::async_test]
async fn ipv6_loopback_looped_back_by_default(driver: DefaultDriver) {
    let mut consomme = Consomme::new({
        let mut params = ConsommeParams::new().unwrap();
        params.skip_ipv6_checks = true;
        params
    });
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac_ipv6;
    let guest_ip = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let len = build_ipv6_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1),
    );
    consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE)
        .unwrap();
    assert_ipv6_looped_back(
        &client,
        gateway_mac,
        guest_mac,
        guest_ip,
        Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1),
    );
}

/// Verify that traffic to IPv6 link-local (fe80::/10) is not blocked by default.
#[pal_async::async_test]
async fn ipv6_link_local_not_blocked_by_default(driver: DefaultDriver) {
    let mut consomme = Consomme::new({
        let mut params = ConsommeParams::new().unwrap();
        params.skip_ipv6_checks = true;
        params
    });
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac_ipv6;
    let guest_ip = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    let len = build_ipv6_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
    );
    let result = consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE);
    let _ = result;
    assert_ipv6_not_looped_back(
        &client,
        guest_ip,
        Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        "IPv6 link-local traffic",
    );
}

/// Verify that traffic to a normal external IP is not blocked.
#[pal_async::async_test]
async fn ipv4_normal_destination_not_blocked(driver: DefaultDriver) {
    let mut consomme = Consomme::new(ConsommeParams::new().unwrap());
    let mut client = TestClient::new(driver);
    let mut buf = vec![0u8; 1514];

    let guest_mac = consomme.params_mut().client_mac;
    let gateway_mac = consomme.params_mut().gateway_mac;
    let guest_ip = consomme.params_mut().client_ip;

    let len = build_ipv4_syn(
        &mut buf,
        guest_mac,
        gateway_mac,
        guest_ip,
        Ipv4Address::new(8, 8, 8, 8),
    );
    let result = consomme
        .access(&mut client)
        .send(&buf[..len], &ChecksumState::NONE);
    let _ = result;
    assert_ipv4_not_looped_back(
        &client,
        guest_ip,
        Ipv4Address::new(8, 8, 8, 8),
        "normal destination",
    );
}

#[test]
fn test_is_same_ipv6_subnet_basic() {
    let a = Ipv6Address::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 1);
    let b = Ipv6Address::new(0x2001, 0x0db8, 0x0001, 0, 0, 0, 0, 2);
    assert!(is_same_ipv6_subnet(a, b, 48));
    assert!(!is_same_ipv6_subnet(a, b, 128));
}

#[test]
fn test_is_same_ipv6_subnet_prefix_zero() {
    let a = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let b = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    assert!(is_same_ipv6_subnet(a, b, 0));
}

#[test]
fn test_is_same_ipv6_subnet_prefix_128_exact_match() {
    let a = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    assert!(is_same_ipv6_subnet(a, a, 128));
}

#[test]
fn test_is_same_ipv6_subnet_prefix_128_no_match() {
    let a = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let b = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
    assert!(!is_same_ipv6_subnet(a, b, 128));
}

#[test]
fn test_is_same_ipv6_subnet_prefix_above_128_does_not_panic() {
    let a = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let b = Ipv6Address::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2);
    // prefix_len > 128 should behave like /128 (exact match), not panic.
    assert!(is_same_ipv6_subnet(a, a, 200));
    assert!(!is_same_ipv6_subnet(a, b, 255));
}
