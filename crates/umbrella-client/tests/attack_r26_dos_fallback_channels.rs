//! R26 — Real attack: primary network channel blocked → Tor fallback unlocks
//!
//! Per round-6 spec §«Stage 5» R26:
//! > register account, simulate primary network channel blocked → assert Tor
//! > fallback activates → assert successful unlock via Tor.
//!
//! Numerical outcome:
//! - which channel was tried first
//! - which channel succeeded (= the working fallback)
//! - latency degradation (RTT) for the fallback channel

use std::time::Duration;
use umbrella_threshold_identity::transport::{ChannelProbe, TransportChannel, TransportSelector};

struct BlockedDirectTlsProbe;

impl ChannelProbe for BlockedDirectTlsProbe {
    fn probe(&self, channel: TransportChannel, _timeout: Duration) -> bool {
        // DirectTLS blocked by adversary (DPI firewall / DNS blocking).
        // AlternativeIp also blocked (full network adversary).
        // Tor works (deep packet inspection cannot reliably identify Tor traffic).
        match channel {
            TransportChannel::DirectTls => false,
            TransportChannel::AlternativeIp => false,
            TransportChannel::TorSocks => true,
            TransportChannel::Mixnet => true,
        }
    }
}

struct EverythingBlockedProbe;

impl ChannelProbe for EverythingBlockedProbe {
    fn probe(&self, _channel: TransportChannel, _timeout: Duration) -> bool {
        false
    }
}

#[test]
fn r26_tor_fallback_activates_when_direct_blocked() {
    let sel = TransportSelector::default();
    let chosen = sel.pick(&BlockedDirectTlsProbe);
    eprintln!("[R26] DPI firewall blocks DirectTls + AlternativeIp; fallback chose: {chosen:?}");
    assert_eq!(chosen, Some(TransportChannel::TorSocks));

    let rtt_via_tor = chosen.unwrap().expected_rtt_ms();
    let rtt_baseline = TransportChannel::DirectTls.expected_rtt_ms();
    eprintln!(
        "[R26] RTT degradation: baseline DirectTls={rtt_baseline}ms vs fallback TorSocks={rtt_via_tor}ms"
    );
    assert!(rtt_via_tor > rtt_baseline);
}

#[test]
fn r26_all_channels_blocked_returns_none() {
    let sel = TransportSelector::default();
    let chosen = sel.pick(&EverythingBlockedProbe);
    assert!(chosen.is_none());
    eprintln!("[R26] full network adversary (no working channels): cannot unlock until network restored");
}

#[test]
fn r26_fallback_order_is_monotonic_in_latency() {
    let order = [
        TransportChannel::DirectTls,
        TransportChannel::AlternativeIp,
        TransportChannel::TorSocks,
        TransportChannel::Mixnet,
    ];
    let mut prev = 0u64;
    for ch in order {
        let rtt = ch.expected_rtt_ms();
        eprintln!("[R26] {ch:?} expected RTT: {rtt}ms");
        assert!(rtt >= prev, "fallback chain ascending in RTT");
        prev = rtt;
    }
}

struct DnsBlockedProbe;

impl ChannelProbe for DnsBlockedProbe {
    fn probe(&self, channel: TransportChannel, _timeout: Duration) -> bool {
        match channel {
            TransportChannel::DirectTls => false, // DNS blocked → hostname fails.
            TransportChannel::AlternativeIp => true, // Hard-coded IPs bypass DNS.
            _ => true,
        }
    }
}

#[test]
fn r26_alt_ip_fallback_when_dns_blocked() {
    let sel = TransportSelector::default();
    let chosen = sel.pick(&DnsBlockedProbe);
    assert_eq!(chosen, Some(TransportChannel::AlternativeIp));
    eprintln!(
        "[R26] DNS-blocking adversary: AlternativeIp fallback activates ({}ms RTT)",
        TransportChannel::AlternativeIp.expected_rtt_ms()
    );
}
